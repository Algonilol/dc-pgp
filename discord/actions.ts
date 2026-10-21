/*
 * DcPgp – vault actions: setup, unlock, lock, password/mode change, key file and vault backup.
 * The crypto and data transforms live in core/ (tested); this file wires them to the running client.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { UserStore } from "@webpack/common";

import { BACKUP_EXTENSION, createBackup, openBackup } from "../core/backup";
import { calibrateArgon2 } from "../core/kdf";
import { emptyVaultData } from "../core/model";
import { generatePassphrase } from "../core/passphrase";
import {
    armorKey, exportProtectedPrivateKey, fingerprintOf, generatePrivateKey, inspectKey, type KeyReport, mergeKeyCopies, minimalPublicKey,
    prepareOwnKey, type PrivateKey, type PublicKey, readPrivateKey, readPublicKey, unlockPrivateKey
} from "../core/pgp";
import { checkStrength, MIN_BITS, type StrengthResult } from "../core/strength";
import {
    createVault, type DeviceMixer, makeSlotA, type OpenVault, openWithPassword, openWithPrivateKey, recoverRawDek,
    type SlotA, type VaultFile, type VaultMode
} from "../core/vault";
import { decodeKeyFile, fileWithHeader, headerForMode, type KeySource, setupNeeds, withoutPrivateKeys, withPrivateKey } from "../core/vaultOps";
import { toastInfo } from "../ui/dialogs";
import { argon2 } from "./argon2";
import { maintainKeys } from "./keyRenewal";
import { deviceStatus, Native, nativeMixer } from "./native";
import { forgetSession, logger, rewriteVault, S, saveVault, type Session, storeGuardTags, storeNewVault } from "./state";
import { dicewareWords } from "./wordlist";

export class DeviceKeyError extends Error {
    constructor(status: string) {
        super(status === "unavailable"
            ? "The Windows device protection (DPAPI) is not available right now. Unlock with your key file."
            : "This PC's device key is missing or unreadable (e.g. after reinstalling Windows). Unlock with your key file and set a new password afterwards.");
        this.name = "DeviceKeyError";
    }
}

function requireSession(): Session {
    if (!S.session) throw new Error("Discord-PGP is locked.");
    return S.session;
}

function userInputs(): string[] {
    const user = UserStore.getCurrentUser();
    return [user?.username, user?.globalName].filter((x): x is string => !!x);
}

export function checkPassword(password: string, generated?: string | null): Promise<StrengthResult> {
    return checkStrength(password, dicewareWords(), userInputs(), generated);
}

export function newPassphrase(): string {
    return generatePassphrase(dicewareWords());
}

async function assertStrong(password: string, generated?: string | null) {
    const r = await checkPassword(password, generated);
    if (!r.ok) throw new Error(`The password is too weak (≈ ${Math.round(r.bits)} bits, ${Math.ceil(MIN_BITS)} needed). Use "Generate" or more random words.`);
}

/** Device key unless DPAPI is unusable; then the password alone protects the vault. */
async function mixerForNewSlot(): Promise<DeviceMixer | null> {
    const status = await deviceStatus();
    if (status === "ok" || status === "missing") return nativeMixer;
    toastInfo("Windows device protection is not available – the vault is protected by the password only.");
    return null;
}

async function newSlotA(rawDek: Uint8Array, password: string): Promise<SlotA> {
    return makeSlotA(rawDek, password, await calibrateArgon2(argon2), argon2, await mixerForNewSlot());
}

async function buildSession(file: VaultFile, open: OpenVault, privateKey?: PrivateKey): Promise<Session> {
    const { data } = open;
    const given = privateKey ?? (data.self.privateKey ? await readPrivateKey(data.self.privateKey) : null);
    if (!given) throw new Error("This vault needs your key file.");
    if (!given.isDecrypted()) throw new Error("The private key is still locked.");
    if (fingerprintOf(given) !== data.self.fpr) throw new Error("This key file does not belong to your vault.");
    const ownPublic = await readPublicKey(data.self.publicKey);
    // A key file can be older than the vault: take over the later expiry from the vault's copy of the key.
    const priv = await mergeKeyCopies(given, ownPublic).catch(e => {
        logger.warn("Could not refresh the key from the vault's copy", e);
        return given;
    });
    const oldPrivate = (await Promise.all(data.oldKeys.filter(k => k.privateKey).map(k => readPrivateKey(k.privateKey!).catch(() => null))))
        .filter((k): k is PrivateKey => k != null);
    const oldPublic = (await Promise.all(data.oldKeys.map(async k => ({ fpr: k.fpr, key: await readPublicKey(k.publicKey).catch(() => null) }))))
        .filter((k): k is { fpr: string; key: PublicKey; } => k.key != null);
    // Own messages are checked against the full key: the copy for contacts only has the newest self-signatures.
    return { file, dek: open.dek, data, privateKey: priv, ownPublic, oldPrivate, ownPublicList: [{ fpr: data.self.fpr, key: priv.toPublic() }, ...oldPublic] };
}

function activate(session: Session) {
    S.session = session;
    S.phase = "unlocked";
    S.emit();
    void maintainKeys(session);
}

export interface PreparedKey {
    key: PrivateKey;
    report: KeyReport;
    source: KeySource;
}

export async function prepareGeneratedKey(name: string): Promise<PreparedKey> {
    const key = await generatePrivateKey(name.trim().slice(0, 64) || "Discord");
    return { key, report: await inspectKey(key), source: "generate" };
}

export async function readKeyFile(file: File): Promise<string | Uint8Array> {
    return decodeKeyFile(new Uint8Array(await file.arrayBuffer()));
}

export async function prepareImportedKey(content: string | Uint8Array, passphrase: string): Promise<PreparedKey> {
    const { key, report } = await prepareOwnKey(await unlockPrivateKey(await readPrivateKey(content), passphrase));
    return { key, report, source: "import" };
}

/** Saves the private key protected with password (importable in Kleopatra). Returns the path or null if cancelled. */
export async function saveKeyFile(key: PrivateKey, password: string, generated?: string | null): Promise<string | null> {
    await assertStrong(password, generated);
    const armored = await exportProtectedPrivateKey(key, password);
    return Native.saveTextFile(`discord-pgp-key-${fingerprintOf(key).slice(-8)}.asc`, armored, "asc");
}

export function exportOwnKeyFile(password: string, generated?: string | null): Promise<string | null> {
    return saveKeyFile(requireSession().privateKey, password, generated);
}

export interface SetupInput {
    prepared: PreparedKey;
    mode: VaultMode;
    password?: string;
    generatedPassword?: string | null;
    keyFileSaved: boolean;
}

export async function setupVault(i: SetupInput): Promise<void> {
    const uid = S.userId;
    if (!uid) throw new Error("No Discord account loaded.");
    if (S.file) throw new Error("Discord-PGP is already set up for this account.");
    const { key, report, source } = i.prepared;
    if (report.errors.length) throw new Error(report.errors.join(" "));
    const needs = setupNeeds(source, i.mode);
    if (needs.keyFile && !i.keyFileSaved)
        throw new Error("Save the key file first. Otherwise the new key only exists in this vault.");

    const stored = i.mode === "stored";
    if (stored) {
        if (!i.password) throw new Error("Please set a password.");
        await assertStrong(i.password, i.generatedPassword);
    }

    const minimal = await minimalPublicKey(key);
    const data = emptyVaultData({
        publicKey: armorKey(minimal),
        fpr: fingerprintOf(key),
        createdAt: Date.now(),
        ...(stored ? { privateKey: armorKey(key) } : {})
    });
    const { file, dek } = await createVault(stored
        ? { mode: "stored", owner: uid, ownPublicKey: minimal, data, password: i.password, params: await calibrateArgon2(argon2), argon2, mixer: await mixerForNewSlot() }
        : { mode: "ram", owner: uid, ownPublicKey: minimal, data });
    if (S.userId !== uid) throw new Error("The Discord account changed. Please set up again.");
    await storeNewVault(file);
    activate(await buildSession(file, { dek, data }, key));
}

export type UnlockInput = { password: string; } | { keyFile: string | Uint8Array; passphrase: string; };

/** Returns viaKeyFile so the UI can offer a new password after a recovery. */
export async function unlockVault(input: UnlockInput): Promise<{ viaKeyFile: boolean; }> {
    const file = S.file;
    if (!file) throw new Error("There is no vault.");
    if (S.session) return { viaKeyFile: false };

    let session: Session;
    if ("password" in input) {
        if (!file.a) throw new Error("This vault is unlocked with the key file (\"RAM only\" mode).");
        let mixer: DeviceMixer | null = null;
        if (file.a.device) {
            const status = await deviceStatus();
            if (status !== "ok") throw new DeviceKeyError(status);
            mixer = nativeMixer;
        }
        session = await buildSession(file, await openWithPassword(file, input.password, argon2, mixer));
    } else {
        const key = await unlockPrivateKey(await readPrivateKey(input.keyFile), input.passphrase);
        if (fingerprintOf(key) !== file.ownFpr) throw new Error("This key file does not belong to your vault.");
        session = await buildSession(file, await openWithPrivateKey(file, key), key);
    }
    if (S.file !== file || S.session) throw new Error("The vault changed in the meantime. Please try again.");
    activate(session);
    return { viaKeyFile: !("password" in input) };
}

export function lockVault(reason?: string) {
    if (!S.session) return;
    forgetSession();
    S.phase = S.file ? "locked" : "nosetup";
    S.emit();
    if (reason) toastInfo(`Discord-PGP locked (${reason}).`);
}

export async function changePassword(newPassword: string, generated?: string | null): Promise<void> {
    const session = requireSession();
    if (session.file.mode !== "stored") throw new Error("In \"RAM only\" mode there is no vault password.");
    await assertStrong(newPassword, generated);
    // A fresh data key: the old password – and any old copy of the vault – no longer opens the current one.
    const fresh = await createVault({
        mode: "stored", owner: session.file.owner, ownPublicKey: session.ownPublic, data: session.data,
        password: newPassword, params: await calibrateArgon2(argon2), argon2, mixer: await mixerForNewSlot()
    });
    await rewriteVault(session, () => {
        session.file = fresh.file;
        session.dek = fresh.dek;
    });
}

/** The own private key as armored text, after the vault password was confirmed again ("Stored" mode only). */
export async function revealPrivateKey(password: string): Promise<string> {
    const session = requireSession();
    const { file } = session;
    if (file.mode !== "stored" || !file.a) throw new Error("In \"RAM only\" mode your private key is only in your key file.");
    let mixer: DeviceMixer | null = null;
    if (file.a.device) {
        const status = await deviceStatus();
        if (status !== "ok") throw new DeviceKeyError(status);
        mixer = nativeMixer;
    }
    await openWithPassword(file, password, argon2, mixer);
    if (S.session !== session) throw new Error("Discord-PGP was locked in the meantime.");
    return armorKey(session.privateKey);
}

export interface ModeOptions {
    /** Required for "stored". */
    password?: string;
    generated?: string | null;
    /** Required for "ram": the user has the key file, since the vault will no longer contain the key. */
    keyFileConfirmed?: boolean;
}

export async function changeSecurityMode(mode: VaultMode, o: ModeOptions = {}): Promise<void> {
    const session = requireSession();
    if (session.file.mode === mode) return;
    if (mode === "ram") {
        if (!o.keyFileConfirmed) throw new Error("\"RAM only\" is not possible without a saved key file.");
        // Rewritten, not just saved: the fallback copy must not keep the private key either.
        return rewriteVault(session, () => {
            session.data = withoutPrivateKeys(session.data);
            session.file = fileWithHeader(session.file, headerForMode(session.file, "ram"));
        });
    } else {
        if (!o.password) throw new Error("Please set a password.");
        await assertStrong(o.password, o.generated);
        const raw = await recoverRawDek(session.file, session.privateKey);
        let slot: SlotA;
        try {
            slot = await newSlotA(raw, o.password);
        } finally {
            raw.fill(0);
        }
        if (S.session !== session) throw new Error("Discord-PGP was locked in the meantime.");
        session.data = withPrivateKey(session.data, armorKey(session.privateKey));
        session.file = fileWithHeader(session.file, headerForMode(session.file, "stored", slot));
    }
    await saveVault();
}

/** Portable backup protected by its own password (no device key). Returns the path or null if cancelled. */
export async function exportVaultBackup(password: string, generated?: string | null): Promise<string | null> {
    const session = requireSession();
    const uid = S.userId!;
    await assertStrong(password, generated);
    const text = await createBackup({ owner: uid, mode: session.file.mode, data: session.data, password, params: await calibrateArgon2(argon2), argon2 });
    return Native.saveTextFile(`discord-pgp-vault-${new Date().toISOString().slice(0, 10)}.${BACKUP_EXTENSION}`, text, BACKUP_EXTENSION);
}

/**
 * Replaces the vault on this PC with a backup. In mode "stored" the backup password
 * becomes this PC's vault password; in "ram" the vault stays locked until the key file is loaded.
 */
export async function importVaultBackup(text: string, password: string): Promise<{ needsKeyFile: boolean; }> {
    const uid = S.userId;
    if (!uid) throw new Error("No Discord account loaded.");
    const restored = await openBackup(text, password, argon2);
    if (restored.owner !== uid) throw new Error("This backup belongs to a different Discord account.");
    const ownPublic = await readPublicKey(restored.data.self.publicKey);

    if (restored.mode === "stored") {
        const key = await readPrivateKey(restored.data.self.privateKey!);
        const { file, dek } = await createVault({
            mode: "stored", owner: uid, ownPublicKey: ownPublic, data: restored.data,
            password, params: await calibrateArgon2(argon2), argon2, mixer: await mixerForNewSlot()
        });
        const session = await buildSession(file, { dek, data: restored.data }, key);
        forgetSession();
        await storeNewVault(file);
        activate(session);
        // Not saveVault(): that would overwrite the fallback copy of the replaced vault that the dialog promises.
        await storeGuardTags();
        return { needsKeyFile: false };
    }

    const { file } = await createVault({ mode: "ram", owner: uid, ownPublicKey: ownPublic, data: restored.data });
    forgetSession();
    await storeNewVault(file);
    await storeGuardTags(restored.data);
    S.phase = "locked";
    S.emit();
    return { needsKeyFile: true };
}
