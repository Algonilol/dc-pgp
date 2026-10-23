/*
 * DcPgp – contacts: incoming keys, key changes, verification and blocking
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { snowflakeTime } from "./format";
import { setChannelEncryption } from "./menus";
import type { Contact, KeyHistoryEntry, VaultData } from "./model";
import { armorKey, fingerprintOf, inspectKey, keyExpiry, type KeyReport, mergeKeyCopies, PgpUserError, type PublicKey, readPublicKey } from "./pgp";

export interface IncomingKey {
    key: PublicKey;
    fpr: string;
    armored: string;
    report: KeyReport;
}

/** Parses and checks a public key received from someone. Throws PgpUserError with a readable reason. */
export async function validateIncomingKey(armoredKey: string): Promise<IncomingKey> {
    const key = await readPublicKey(armoredKey);
    const report = await inspectKey(key);
    if (report.errors.length) throw new PgpUserError(report.errors.join(" "));
    return { key, fpr: fingerprintOf(key), armored: armorKey(key), report };
}

export type IncomingKeyState =
    | { state: "new"; }
    | { state: "same"; }
    | { state: "changed"; previousFpr: string; }
    | { state: "own-key"; }
    | { state: "belongs-to-other"; otherUserId: string; otherName: string; };

export function classifyIncomingKey(fpr: string, authorId: string, data: VaultData): IncomingKeyState {
    const ownFprs = [data.self.fpr, ...data.oldKeys.map(k => k.fpr)];
    if (ownFprs.includes(fpr)) return { state: "own-key" };

    for (const c of Object.values(data.contacts)) {
        if (c.userId === authorId) continue;
        if (c.fpr === fpr || c.history.some(h => h.fpr === fpr) || c.pendingKey?.fpr === fpr)
            return { state: "belongs-to-other", otherUserId: c.userId, otherName: c.name };
    }

    const existing = data.contacts[authorId];
    if (!existing) return { state: "new" };
    if (existing.fpr === fpr) return { state: "same" };
    return { state: "changed", previousFpr: existing.fpr };
}

const expiryOf = (incoming: IncomingKey) => incoming.report.expires?.getTime() ?? null;

/**
 * When the current key counts as replaced: when the new one was announced, by Discord's (server) time of
 * the key message – no PC clock involved. An announcement older than the current key itself is stale (an old
 * key message accepted late), so then it is the moment the user accepted it.
 */
function switchTime(current: Contact, announcedAt: number | null, now: number): number {
    return announcedAt != null && announcedAt > current.addedAt ? announcedAt : now;
}

/** The current key moves to the history; the incoming one leaves it, so a key used again starts afresh. */
function retireCurrentKey(current: Contact, incomingFpr: string, replacedAt: number): KeyHistoryEntry[] {
    const rest = current.history.filter(h => h.fpr !== current.fpr && h.fpr !== incomingFpr);
    return [{ publicKey: current.publicKey, fpr: current.fpr, replacedAt }, ...rest].slice(0, 10);
}

/** `messageId`: the key message, whose Discord time dates the key change. */
export function addOrReplaceContact(data: VaultData, userId: string, name: string, incoming: IncomingKey, now = Date.now(), messageId?: string): Contact {
    const existing = data.contacts[userId];
    const history = !existing ? []
        : existing.fpr === incoming.fpr ? existing.history
            : retireCurrentKey(existing, incoming.fpr, switchTime(existing, snowflakeTime(messageId), now));

    const contact: Contact = {
        userId,
        name,
        publicKey: incoming.armored,
        fpr: incoming.fpr,
        verified: existing?.fpr === incoming.fpr ? existing.verified : false,
        ...(existing?.fpr === incoming.fpr && existing.verifiedAt ? { verifiedAt: existing.verifiedAt } : {}),
        addedAt: existing?.fpr === incoming.fpr ? existing.addedAt : now,
        history,
        keyExpires: expiryOf(incoming),
        // Which copy of OUR key they have does not depend on their key.
        ...(existing?.sentKeyAt != null ? { sentKeyAt: existing.sentKeyAt } : {})
    };
    data.contacts[userId] = contact;
    return contact;
}

/** Marks a different incoming key as pending: encryption to this person pauses until the user decides. */
export function markKeyChange(data: VaultData, userId: string, incoming: IncomingKey, messageId?: string, now = Date.now()) {
    const c = data.contacts[userId];
    if (!c) return;
    c.pendingKey = { publicKey: incoming.armored, fpr: incoming.fpr, at: now, ...(messageId ? { messageId } : {}), keyExpires: expiryOf(incoming) };
}

export interface KeyRefresh {
    publicKey: string;
    keyExpires: number | null;
}

/**
 * Takes over what a new copy of a contact's stored key adds, e.g. the later expiry of an extended key.
 * Same fingerprint only; null when the copy adds nothing. The verification stays: key material and
 * safety number are unchanged.
 */
export async function refreshContactKey(contact: Contact, incoming: IncomingKey, now = new Date()): Promise<KeyRefresh | null> {
    if (incoming.fpr !== contact.fpr) return null;
    const stored = await readPublicKey(contact.publicKey);
    const merged = await mergeKeyCopies(stored, incoming.key, now);
    const armored = armorKey(merged);
    if (armored === armorKey(stored)) return null;
    return { publicKey: armored, keyExpires: await keyExpiry(merged) };
}

export function applyKeyRefresh(data: VaultData, userId: string, refresh: KeyRefresh) {
    const c = data.contacts[userId];
    if (!c) return;
    c.publicKey = refresh.publicKey;
    c.keyExpires = refresh.keyExpires;
}

export function rejectPendingKey(data: VaultData, userId: string): boolean {
    const c = data.contacts[userId];
    if (!c?.pendingKey) return false;
    delete c.pendingKey;
    return true;
}

/**
 * Derived from the stored fields (blocked map, pendingKey, verified), so it can never drift:
 * trusted = safety number compared, unverified = key stored but not compared,
 * changed = a different key arrived and awaits a decision, blocked, none = no key.
 */
export type ContactStatus = "trusted" | "unverified" | "changed" | "blocked" | "none";

export function contactStatus(data: VaultData, userId: string): ContactStatus {
    if (data.blocked[userId]) return "blocked";
    const c = data.contacts[userId];
    if (!c) return "none";
    if (c.pendingKey) return "changed";
    return c.verified ? "trusted" : "unverified";
}

export function setVerified(data: VaultData, userId: string, verified: boolean, now = Date.now()): boolean {
    const c = data.contacts[userId];
    if (!c || c.pendingKey) return false;
    c.verified = verified;
    if (verified) c.verifiedAt = now;
    else delete c.verifiedAt;
    return true;
}

export function blockUser(data: VaultData, userId: string, now = Date.now()) {
    data.blocked[userId] = now;
    delete data.outgoing[userId];
}

export function unblockUser(data: VaultData, userId: string) {
    delete data.blocked[userId];
}

export function removeContact(data: VaultData, userId: string): boolean {
    if (!data.contacts[userId]) return false;
    delete data.contacts[userId];
    return true;
}

/**
 * "Remove contact": forgets the key (with any pending key change) and our open request, and stops
 * encrypting the DM. Decisions about old key messages (handled) and blocking stay untouched, so old
 * key messages are not offered again and a block survives.
 */
export function forgetContact(data: VaultData, userId: string, dmChannelId: string | null): boolean {
    let changed = removeContact(data, userId);
    if (data.outgoing[userId]) {
        delete data.outgoing[userId];
        changed = true;
    }
    if (dmChannelId && data.channels[dmChannelId]?.encrypt) {
        setChannelEncryption(data, dmChannelId, false);
        changed = true;
    }
    return changed;
}

export function acceptPendingKey(data: VaultData, userId: string, now = Date.now()): Contact | null {
    const c = data.contacts[userId];
    if (!c?.pendingKey) return null;
    const { publicKey, fpr, keyExpires, messageId } = c.pendingKey;
    c.history = retireCurrentKey(c, fpr, switchTime(c, snowflakeTime(messageId), now));
    c.publicKey = publicKey;
    c.fpr = fpr;
    c.addedAt = now;
    c.verified = false;
    delete c.verifiedAt;
    delete c.pendingKey;
    // Unknown for key changes stored by older versions: computed again after the next unlock.
    if (keyExpires !== undefined) c.keyExpires = keyExpires;
    else delete c.keyExpires;
    return c;
}
