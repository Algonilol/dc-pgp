/*
 * DcPgp – portable vault backup: the vault content encrypted with a backup password only
 * (Argon2id + AES-256-GCM, no device key), so it can be restored on another PC.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { asBufferSource, fromBase64, fromUtf8, randomBytes, toBase64, utf8 } from "./bytes";
import { type Argon2Fn, type Argon2Params, passwordBytes, validateArgon2Params } from "./kdf";
import { normalizeVaultData, type VaultData } from "./model";
import { VaultCorruptError, type VaultMode } from "./vault";

export const BACKUP_TYPE = "dcpgp-vault-backup";
export const BACKUP_EXTENSION = "dcpgp";

export interface BackupFile {
    type: typeof BACKUP_TYPE;
    v: 1;
    owner: string;
    ownFpr: string;
    mode: VaultMode;
    created: number;
    kdf: { alg: "argon2id"; salt: string; m: number; t: number; p: number; };
    iv: string;
    ct: string;
}

export interface RestoredBackup {
    owner: string;
    mode: VaultMode;
    created: number;
    data: VaultData;
}

export class BackupPasswordError extends Error {
    constructor() {
        super("Wrong password, or the backup file was modified.");
        this.name = "BackupPasswordError";
    }
}

function aad(f: Omit<BackupFile, "iv" | "ct">): Uint8Array {
    return utf8(`dcpgp backup v1|${f.owner}|${f.ownFpr}|${f.mode}|${f.created}|${f.kdf.salt}|${f.kdf.m}|${f.kdf.t}|${f.kdf.p}`);
}

async function backupKey(password: string, kdf: BackupFile["kdf"], argon2: Argon2Fn): Promise<CryptoKey> {
    const params: Argon2Params = { m: kdf.m, t: kdf.t, p: kdf.p };
    validateArgon2Params(params);
    const salt = fromBase64(kdf.salt);
    const stretched = await argon2(passwordBytes(password), salt, params);
    const base = await crypto.subtle.importKey("raw", asBufferSource(stretched), "HKDF", false, ["deriveKey"]);
    stretched.fill(0);
    return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: asBufferSource(salt), info: asBufferSource(utf8("dcpgp backup v1")) },
        base,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export interface CreateBackupOptions {
    owner: string;
    mode: VaultMode;
    data: VaultData;
    password: string;
    params: Argon2Params;
    argon2: Argon2Fn;
    now?: number;
}

export async function createBackup(o: CreateBackupOptions): Promise<string> {
    validateArgon2Params(o.params);
    const header: Omit<BackupFile, "iv" | "ct"> = {
        type: BACKUP_TYPE,
        v: 1,
        owner: o.owner,
        ownFpr: o.data.self.fpr,
        mode: o.mode,
        created: o.now ?? Date.now(),
        kdf: { alg: "argon2id", salt: toBase64(randomBytes(16)), ...o.params }
    };
    const key = await backupKey(o.password, header.kdf, o.argon2);
    const iv = randomBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: asBufferSource(iv), additionalData: asBufferSource(aad(header)) },
        key,
        asBufferSource(utf8(JSON.stringify(o.data)))
    ));
    const file: BackupFile = { ...header, iv: toBase64(iv), ct: toBase64(ct) };
    return JSON.stringify(file, null, 2);
}

export function parseBackupFile(text: string): BackupFile {
    let f: any;
    try {
        f = JSON.parse(text);
    } catch {
        throw new VaultCorruptError("not a valid backup file");
    }
    const ok = f && typeof f === "object" && f.type === BACKUP_TYPE && f.v === 1
        && typeof f.owner === "string" && typeof f.ownFpr === "string"
        && (f.mode === "stored" || f.mode === "ram") && Number.isFinite(f.created)
        && f.kdf?.alg === "argon2id" && typeof f.kdf.salt === "string"
        && typeof f.iv === "string" && typeof f.ct === "string";
    if (!ok) throw new VaultCorruptError("not a valid backup file");
    validateArgon2Params({ m: f.kdf.m, t: f.kdf.t, p: f.kdf.p });
    return f as BackupFile;
}

export async function openBackup(text: string, password: string, argon2: Argon2Fn): Promise<RestoredBackup> {
    const file = parseBackupFile(text);
    const key = await backupKey(password, file.kdf, argon2);
    let plain: Uint8Array;
    try {
        plain = new Uint8Array(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: asBufferSource(fromBase64(file.iv)), additionalData: asBufferSource(aad(file)) },
            key,
            asBufferSource(fromBase64(file.ct))
        ));
    } catch {
        throw new BackupPasswordError();
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(fromUtf8(plain));
    } catch {
        throw new VaultCorruptError("backup content invalid");
    }
    const data = normalizeVaultData(parsed);
    if (data.self.fpr !== file.ownFpr) throw new VaultCorruptError("backup content does not match the key");
    if (file.mode === "stored" && !data.self.privateKey) throw new VaultCorruptError("backup in \"Stored\" mode without a private key");
    return { owner: file.owner, mode: file.mode, created: file.created, data };
}
