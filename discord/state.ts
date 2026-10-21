/*
 * DcPgp – runtime state: lock phase, the open vault, caches. Plaintext and keys live only here, in memory.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as DataStore from "@api/DataStore";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Logger } from "@utils/Logger";
import { showToast, useEffect, useReducer } from "@webpack/common";

import { fromBase64, randomBytes, toBase64, toHex, utf8 } from "../core/bytes";
import { type Contact, pruneVaultData, type VaultData } from "../core/model";
import { type PrivateKey, type PublicKey, readPublicKey } from "../core/pgp";
import { headerOf, sealVault, validateVaultFile, type VaultFile } from "../core/vault";
import { Native } from "./native";

export const logger = new Logger("DcPgp", "#43b581");

export type Phase = "loading" | "nosetup" | "locked" | "unlocked";

export interface Session {
    file: VaultFile;
    dek: CryptoKey;
    data: VaultData;
    privateKey: PrivateKey;
    ownPublic: PublicKey;
    oldPrivate: PrivateKey[];
    /** Own current and retired public keys, current first. */
    ownPublicList: { fpr: string; key: PublicKey; }[];
}

class State {
    phase: Phase = "loading";
    userId: string | null = null;
    file: VaultFile | null = null;
    session: Session | null = null;
    guardKey: Uint8Array | null = null;
    guardTags = new Set<string>();
    /** False once a send or edit reached Discord without passing our hook (e.g. after a Discord update). */
    hookHealthy = true;
    hookProblem: string | null = null;
    /** Channels where the next message is encrypted once. */
    oneShot = new Set<string>();
    /** Message ids the user decrypted by hand while auto-decrypt is off. */
    revealed = new Set<string>();
    version = 0;
    private listeners = new Set<() => void>();

    subscribe(fn: () => void) {
        this.listeners.add(fn);
        return () => void this.listeners.delete(fn);
    }

    emit() {
        this.version++;
        for (const fn of [...this.listeners]) {
            try { fn(); } catch (e) { logger.error("listener", e); }
        }
    }
}

export const S = new State();

/** Re-renders the component whenever the mod's state changes (lock, contacts, settings). */
export function useDcPgpState(): State {
    const [, force] = useReducer((x: number) => x + 1, 0);
    useEffect(() => S.subscribe(force), []);
    return S;
}

const vaultKey = (uid: string) => `dcpgp-vault:${uid}`;
const vaultPrevKey = (uid: string) => `dcpgp-vault-prev:${uid}`;
const guardTagsKey = (uid: string) => `dcpgp-guard:${uid}`;
const guardFallbackKey = (uid: string) => `dcpgp-guardkey:${uid}`;

async function loadGuardKey(uid: string): Promise<Uint8Array> {
    try {
        const key = await Native.guardKey();
        if (key?.length === 32) return new Uint8Array(key);
    } catch (e) {
        logger.warn("Device key for the chat guard not available, using a local fallback", e);
    }
    const stored = await DataStore.get<string>(guardFallbackKey(uid));
    if (stored) return fromBase64(stored);
    const fresh = randomBytes(32);
    await DataStore.set(guardFallbackKey(uid), toBase64(fresh));
    return fresh;
}

export function guardTag(channelId: string): string | null {
    if (!S.guardKey) return null;
    return toHex(hmac(sha256, S.guardKey, utf8("dcpgp-guard|" + channelId))).slice(0, 32);
}

/** Works while locked too: the ids of encrypted chats are kept as keyed hashes. */
export function isChannelEncrypted(channelId: string | null | undefined): boolean {
    if (!channelId) return false;
    if (S.session) return S.session.data.channels[channelId]?.encrypt === true;
    const tag = guardTag(channelId);
    return tag != null && S.guardTags.has(tag);
}

/** Stores which chats are encrypted (as keyed hashes) so the send protection knows them while locked. */
export async function storeGuardTags(data: VaultData | undefined = S.session?.data) {
    if (!data || !S.userId) return;
    const tags = Object.entries(data.channels)
        .filter(([, p]) => p.encrypt)
        .map(([cid]) => guardTag(cid))
        .filter((t): t is string => t != null);
    S.guardTags = new Set(tags);
    await DataStore.set(guardTagsKey(S.userId), tags);
}

/** Loads (but does not open) the vault of the logged-in account. */
export async function loadForUser(userId: string) {
    if (S.userId === userId && S.phase !== "loading") return;
    forgetSession();
    S.userId = userId;
    S.file = null;
    S.guardKey = await loadGuardKey(userId);
    S.guardTags = new Set(await DataStore.get<string[]>(guardTagsKey(userId)) ?? []);

    const raw = await DataStore.get(vaultKey(userId));
    if (raw == null) {
        S.phase = "nosetup";
        S.emit();
        return;
    }
    try {
        S.file = validateVaultFile(raw);
    } catch (e) {
        logger.error("Vault unreadable, trying the previous version", e);
        const prev = await DataStore.get(vaultPrevKey(userId));
        S.file = prev ? validateVaultFile(prev) : null;
        if (S.file) showToast({ text: "DcPgp: the vault was damaged, loaded the previous version.", variant: "critical" });
    }
    S.phase = S.file ? "locked" : "nosetup";
    S.emit();
}

/** Writes a freshly created vault (setup or reset). */
export async function storeNewVault(file: VaultFile) {
    if (!S.userId) throw new Error("No Discord account loaded");
    const old = await DataStore.get(vaultKey(S.userId));
    if (old) await DataStore.set(vaultPrevKey(S.userId), old);
    await DataStore.set(vaultKey(S.userId), file);
    S.file = file;
}

let saveChain: Promise<void> = Promise.resolve();

/** Re-encrypts and stores the open vault. Calls are serialised. */
export function saveVault(): Promise<void> {
    saveChain = saveChain.then(async () => {
        const session = S.session;
        const uid = S.userId;
        if (!session || !uid) return;
        pruneVaultData(session.data);
        const file = await sealVault(headerOf(session.file), session.dek, session.data);
        const previous = await DataStore.get(vaultKey(uid));
        if (previous) await DataStore.set(vaultPrevKey(uid), previous);
        await DataStore.set(vaultKey(uid), file);
        session.file = file;
        S.file = file;
        await storeGuardTags();
    }).catch(e => {
        logger.error("Saving the vault failed", e);
        showToast({ text: "DcPgp: the vault could not be saved!", variant: "critical" });
    });
    S.emit();
    return saveChain;
}

/**
 * Like saveVault, in the same queue, but the fallback copy is replaced too: after removing the stored
 * private key or changing the password, no older copy may keep the key or the old password slot.
 * update() runs right before writing, so no queued save can mix old and new. Errors reach the caller.
 */
export function rewriteVault(session: Session, update: () => void): Promise<void> {
    const run = saveChain.then(async () => {
        const uid = S.userId;
        if (S.session !== session || !uid) throw new Error("DcPgp was locked in the meantime.");
        update();
        pruneVaultData(session.data);
        const file = await sealVault(headerOf(session.file), session.dek, session.data);
        await DataStore.set(vaultKey(uid), file);
        await DataStore.set(vaultPrevKey(uid), file);
        session.file = file;
        S.file = file;
        await storeGuardTags();
    });
    saveChain = run.catch(e => logger.error("Rewriting the vault failed", e));
    return run.finally(() => S.emit());
}

export async function deleteVaultForUser() {
    const uid = S.userId;
    if (!uid) return;
    forgetSession();
    await DataStore.delMany([vaultKey(uid), vaultPrevKey(uid), guardTagsKey(uid)]);
    S.file = null;
    S.guardTags.clear();
    S.phase = "nosetup";
    S.emit();
}

const keyCache = new Map<string, Promise<PublicKey>>();

/** Parsed public keys, cached by their armored text. Cleared on lock. */
export function parsedKey(armored: string): Promise<PublicKey> {
    let p = keyCache.get(armored);
    if (!p) {
        p = readPublicKey(armored);
        p.catch(() => keyCache.delete(armored));
        keyCache.set(armored, p);
    }
    return p;
}

const lockListeners = new Set<() => void>();
export function onLock(fn: () => void) {
    lockListeners.add(fn);
    return () => void lockListeners.delete(fn);
}

/** Drops every secret from memory (keys, vault content, plaintext caches). */
export function forgetSession() {
    S.session = null;
    S.oneShot.clear();
    S.revealed.clear();
    keyCache.clear();
    for (const fn of lockListeners) {
        try { fn(); } catch (e) { logger.error("lock listener", e); }
    }
}

export function contactOf(userId: string | null | undefined): Contact | null {
    if (!userId || !S.session) return null;
    return S.session.data.contacts[userId] ?? null;
}

export function myId(): string | null {
    return S.userId;
}
