/*
 * DcPgp – the vault: contacts, keys and chat settings, encrypted with a data key that is wrapped
 * by the password (+ device key) and by the own OpenPGP key (recovery)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { asBufferSource, fromBase64, fromUtf8, randomBytes, toBase64, utf8 } from "./bytes";
import { type Argon2Fn, type Argon2Params, passwordBytes, validateArgon2Params } from "./kdf";
import { normalizeVaultData, type VaultData } from "./model";
import { decryptWithKeys, encryptToKeys, type PrivateKey, type PublicKey } from "./pgp";

export type VaultMode = "stored" | "ram";

export interface SlotA {
    kdf: { alg: "argon2id"; salt: string; m: number; t: number; p: number; };
    /** Whether the device key (Windows DPAPI via Electron safeStorage) is mixed in. */
    device: boolean;
    iv: string;
    ct: string;
}

export interface SlotB {
    /** Data key encrypted to the owner's own OpenPGP key (recovery with the key from Kleopatra). */
    pgp: string;
}

export interface VaultHeader {
    v: 1;
    mode: VaultMode;
    owner: string;
    ownFpr: string;
    created: number;
    a?: SlotA;
    b: SlotB;
}

export interface VaultFile extends VaultHeader {
    updated: number;
    iv: string;
    ct: string;
}

/** Combines the Argon2 output with the device secret; implemented in the native (main process) part. */
export type DeviceMixer = (argonOutput: Uint8Array, salt: Uint8Array) => Promise<Uint8Array>;

export class WrongPasswordError extends Error {
    constructor() {
        super("Wrong password.");
        this.name = "WrongPasswordError";
    }
}

export class VaultCorruptError extends Error {
    constructor(detail: string) {
        super("Vault damaged: " + detail);
        this.name = "VaultCorruptError";
    }
}

const SLOT_A_INFO_NO_DEVICE = "dcpgp vault slotA v1 (no device)";
const SLOT_A_AAD = "dcpgp vault slotA v1";

function payloadAad(h: Pick<VaultHeader, "v" | "mode" | "owner" | "ownFpr">): Uint8Array {
    return utf8(`dcpgp vault payload|${h.v}|${h.mode}|${h.owner}|${h.ownFpr}`);
}

async function aesKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
    if (raw.length !== 32) throw new Error("AES key must be 32 bytes long");
    return crypto.subtle.importKey("raw", asBufferSource(raw), { name: "AES-GCM" }, false, usages);
}

async function aesEncrypt(key: CryptoKey, plain: Uint8Array, aad: Uint8Array) {
    const iv = randomBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBufferSource(iv), additionalData: asBufferSource(aad) }, key, asBufferSource(plain)));
    return { iv: toBase64(iv), ct: toBase64(ct) };
}

async function aesDecrypt(key: CryptoKey, iv: string, ct: string, aad: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: asBufferSource(fromBase64(iv)), additionalData: asBufferSource(aad) },
        key,
        asBufferSource(fromBase64(ct))
    ));
}

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array> {
    const base = await crypto.subtle.importKey("raw", asBufferSource(ikm), "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: asBufferSource(salt), info: asBufferSource(utf8(info)) }, base, 256);
    return new Uint8Array(bits);
}

async function slotKey(password: string, kdf: SlotA["kdf"], device: boolean, argon2: Argon2Fn, mixer: DeviceMixer | null): Promise<CryptoKey> {
    const params: Argon2Params = { m: kdf.m, t: kdf.t, p: kdf.p };
    validateArgon2Params(params);
    const salt = fromBase64(kdf.salt);
    const stretched = await argon2(passwordBytes(password), salt, params);
    let kek: Uint8Array;
    if (device) {
        if (!mixer) throw new Error("Device key not available");
        kek = await mixer(stretched, salt);
    } else {
        kek = await hkdf(stretched, salt, SLOT_A_INFO_NO_DEVICE);
    }
    stretched.fill(0);
    const key = await aesKey(kek, ["encrypt", "decrypt"]);
    kek.fill(0);
    return key;
}

export async function makeSlotA(rawDek: Uint8Array, password: string, params: Argon2Params, argon2: Argon2Fn, mixer: DeviceMixer | null): Promise<SlotA> {
    validateArgon2Params(params);
    const kdf: SlotA["kdf"] = { alg: "argon2id", salt: toBase64(randomBytes(16)), ...params };
    const device = mixer != null;
    const key = await slotKey(password, kdf, device, argon2, mixer);
    const { iv, ct } = await aesEncrypt(key, rawDek, utf8(SLOT_A_AAD));
    return { kdf, device, iv, ct };
}

export async function makeSlotB(rawDek: Uint8Array, ownKeys: PublicKey[]): Promise<SlotB> {
    return { pgp: await encryptToKeys(rawDek, ownKeys) };
}

export interface OpenVault {
    dek: CryptoKey;
    data: VaultData;
}

async function openPayload(file: VaultFile, rawDek: Uint8Array): Promise<OpenVault> {
    const dek = await aesKey(rawDek, ["encrypt", "decrypt"]);
    let plain: Uint8Array;
    try {
        plain = await aesDecrypt(dek, file.iv, file.ct, payloadAad(file));
    } catch {
        throw new VaultCorruptError("content cannot be decrypted (modified or damaged)");
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(fromUtf8(plain));
    } catch {
        throw new VaultCorruptError("invalid format");
    }
    const data = normalizeVaultData(parsed);
    if (data.self.fpr !== file.ownFpr) throw new VaultCorruptError("key does not match the vault");
    return { dek, data };
}

export function validateVaultFile(raw: unknown): VaultFile {
    const f = raw as VaultFile;
    const ok = f && typeof f === "object" && f.v === 1 && (f.mode === "stored" || f.mode === "ram")
        && typeof f.owner === "string" && typeof f.ownFpr === "string"
        && typeof f.iv === "string" && typeof f.ct === "string"
        && f.b && typeof f.b.pgp === "string"
        && (f.a == null || (typeof f.a.iv === "string" && typeof f.a.ct === "string" && f.a.kdf?.alg === "argon2id" && typeof f.a.kdf.salt === "string"));
    if (!ok) throw new VaultCorruptError("unknown file format");
    return f;
}

export async function openWithPassword(file: VaultFile, password: string, argon2: Argon2Fn, mixer: DeviceMixer | null): Promise<OpenVault> {
    if (!file.a) throw new Error("This vault has no password access (\"RAM only\" mode).");
    const key = await slotKey(password, file.a.kdf, file.a.device, argon2, mixer);
    let rawDek: Uint8Array;
    try {
        rawDek = await aesDecrypt(key, file.a.iv, file.a.ct, utf8(SLOT_A_AAD));
    } catch {
        throw new WrongPasswordError();
    }
    try {
        return await openPayload(file, rawDek);
    } finally {
        rawDek.fill(0);
    }
}

export async function openWithPrivateKey(file: VaultFile, privateKey: PrivateKey): Promise<OpenVault> {
    const rawDek = await decryptWithKeys(file.b.pgp, [privateKey]);
    try {
        return await openPayload(file, rawDek);
    } finally {
        rawDek.fill(0);
    }
}

/** Raw data key, recovered through the own private key. Needed to rewrap slots while unlocked. */
export async function recoverRawDek(file: VaultFile, privateKey: PrivateKey): Promise<Uint8Array> {
    return decryptWithKeys(file.b.pgp, [privateKey]);
}

export async function sealVault(header: VaultHeader, dek: CryptoKey, data: VaultData): Promise<VaultFile> {
    const { iv, ct } = await aesEncrypt(dek, utf8(JSON.stringify(data)), payloadAad(header));
    return {
        v: 1,
        mode: header.mode,
        owner: header.owner,
        ownFpr: header.ownFpr,
        created: header.created,
        ...(header.a ? { a: header.a } : {}),
        b: header.b,
        updated: Date.now(),
        iv,
        ct
    };
}

export interface CreateVaultOptions {
    mode: VaultMode;
    owner: string;
    ownPublicKey: PublicKey;
    data: VaultData;
    password?: string;
    params?: Argon2Params;
    argon2?: Argon2Fn;
    mixer?: DeviceMixer | null;
}

export async function createVault(o: CreateVaultOptions): Promise<{ file: VaultFile; dek: CryptoKey; }> {
    const rawDek = randomBytes(32);
    try {
        let a: SlotA | undefined;
        if (o.mode === "stored") {
            if (!o.password || !o.params || !o.argon2) throw new Error("The \"Stored\" mode needs a password.");
            a = await makeSlotA(rawDek, o.password, o.params, o.argon2, o.mixer ?? null);
        }
        const b = await makeSlotB(rawDek, [o.ownPublicKey]);
        const header: VaultHeader = { v: 1, mode: o.mode, owner: o.owner, ownFpr: o.data.self.fpr, created: Date.now(), ...(a ? { a } : {}), b };
        const dek = await aesKey(rawDek, ["encrypt", "decrypt"]);
        const file = await sealVault(header, dek, o.data);
        return { file, dek };
    } finally {
        rawDek.fill(0);
    }
}

export function headerOf(file: VaultFile): VaultHeader {
    return { v: file.v, mode: file.mode, owner: file.owner, ownFpr: file.ownFpr, created: file.created, ...(file.a ? { a: file.a } : {}), b: file.b };
}
