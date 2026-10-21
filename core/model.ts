/*
 * DcPgp – what the vault stores (own keys, contacts, chat settings) and its validation
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export interface OwnKey {
    /** Armored, unprotected private key. Only present in mode "stored". */
    privateKey?: string;
    /** Armored minimal public key that is sent to contacts. */
    publicKey: string;
    fpr: string;
    createdAt: number;
    /** When the key's validity was last extended; contacts who got their copy before need the new one. */
    renewedAt?: number;
}

export interface RetiredKey {
    privateKey?: string;
    publicKey: string;
    fpr: string;
    retiredAt: number;
}

export interface KeyHistoryEntry {
    publicKey: string;
    fpr: string;
    replacedAt: number;
}

export interface PendingKeyChange {
    publicKey: string;
    fpr: string;
    at: number;
    messageId?: string;
    keyExpires?: number | null;
}

export interface Contact {
    userId: string;
    name: string;
    publicKey: string;
    fpr: string;
    verified: boolean;
    verifiedAt?: number;
    addedAt: number;
    history: KeyHistoryEntry[];
    /** A different key arrived for this person; encryption to them pauses until the user decides. */
    pendingKey?: PendingKeyChange;
    /** When the stored key expires (ms; null: never). Missing until it is computed once after unlocking. */
    keyExpires?: number | null;
    /** When we last sent our own key to this person. */
    sentKeyAt?: number;
}

export type Target =
    | { kind: "all"; }
    | { kind: "members"; userIds: string[]; }
    | { kind: "role"; roleId: string; };

export interface ChannelPrefs {
    encrypt: boolean;
    since?: number;
    target?: Target;
    autoDecrypt?: boolean;
}

export type HandledResult = "accepted" | "declined" | "blocked" | "stored";

export interface VaultData {
    v: 1;
    self: OwnKey;
    oldKeys: RetiredKey[];
    contacts: Record<string, Contact>;
    blocked: Record<string, number>;
    /** Key requests we sent and are waiting for. */
    outgoing: Record<string, { at: number; channelId: string; }>;
    /** Incoming key messages we already acted on, by message id. */
    handled: Record<string, { at: number; result: HandledResult; }>;
    channels: Record<string, ChannelPrefs>;
}

export function emptyVaultData(self: OwnKey): VaultData {
    return { v: 1, self, oldKeys: [], contacts: {}, blocked: {}, outgoing: {}, handled: {}, channels: {} };
}

const isObj = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const isStr = (x: unknown): x is string => typeof x === "string";
const isNum = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x);
const SNOWFLAKE = /^\d{1,25}$/;

/** A stored key expiry: a time, null (never) or absent (not computed yet). */
const keyExpiresOf = (x: unknown) => isNum(x) || x === null ? { keyExpires: x } : {};

function pickRecord<T>(raw: unknown, map: (key: string, value: any) => T | null): Record<string, T> {
    const out: Record<string, T> = {};
    if (!isObj(raw)) return out;
    for (const [k, v] of Object.entries(raw)) {
        if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
        const mapped = map(k, v);
        if (mapped != null) out[k] = mapped;
    }
    return out;
}

function normalizeTarget(t: unknown): Target | undefined {
    if (!isObj(t)) return undefined;
    if (t.kind === "all") return { kind: "all" };
    if (t.kind === "role" && isStr(t.roleId) && SNOWFLAKE.test(t.roleId)) return { kind: "role", roleId: t.roleId };
    if (t.kind === "members" && Array.isArray(t.userIds))
        return { kind: "members", userIds: t.userIds.filter((id: unknown) => isStr(id) && SNOWFLAKE.test(id)).slice(0, 200) };
    return undefined;
}

/** Defensive copy of decrypted vault data: drops anything malformed instead of failing to unlock. */
export function normalizeVaultData(raw: unknown): VaultData {
    if (!isObj(raw) || !isObj(raw.self) || !isStr(raw.self.publicKey) || !isStr(raw.self.fpr))
        throw new Error("Vault content damaged");

    const self: OwnKey = {
        publicKey: raw.self.publicKey,
        fpr: raw.self.fpr,
        createdAt: isNum(raw.self.createdAt) ? raw.self.createdAt : Date.now(),
        ...(isStr(raw.self.privateKey) ? { privateKey: raw.self.privateKey } : {}),
        ...(isNum(raw.self.renewedAt) ? { renewedAt: raw.self.renewedAt } : {})
    };

    const oldKeys: RetiredKey[] = Array.isArray(raw.oldKeys)
        ? raw.oldKeys.filter((k: any) => isObj(k) && isStr(k.publicKey) && isStr(k.fpr)).map((k: any) => ({
            publicKey: k.publicKey,
            fpr: k.fpr,
            retiredAt: isNum(k.retiredAt) ? k.retiredAt : 0,
            ...(isStr(k.privateKey) ? { privateKey: k.privateKey } : {})
        }))
        : [];

    const contacts = pickRecord<Contact>(raw.contacts, (id, c) => {
        if (!SNOWFLAKE.test(id) || !isObj(c) || !isStr(c.publicKey) || !isStr(c.fpr)) return null;
        const history = Array.isArray(c.history)
            ? c.history.filter((h: any) => isObj(h) && isStr(h.publicKey) && isStr(h.fpr))
                .map((h: any) => ({ publicKey: h.publicKey, fpr: h.fpr, replacedAt: isNum(h.replacedAt) ? h.replacedAt : 0 }))
            : [];
        const pending = isObj(c.pendingKey) && isStr(c.pendingKey.publicKey) && isStr(c.pendingKey.fpr)
            ? {
                publicKey: c.pendingKey.publicKey, fpr: c.pendingKey.fpr, at: isNum(c.pendingKey.at) ? c.pendingKey.at : 0,
                ...(isStr(c.pendingKey.messageId) ? { messageId: c.pendingKey.messageId } : {}),
                ...keyExpiresOf(c.pendingKey.keyExpires)
            }
            : undefined;
        return {
            userId: id,
            name: isStr(c.name) ? c.name : id,
            publicKey: c.publicKey,
            fpr: c.fpr,
            verified: c.verified === true,
            ...(isNum(c.verifiedAt) ? { verifiedAt: c.verifiedAt } : {}),
            addedAt: isNum(c.addedAt) ? c.addedAt : 0,
            history,
            ...(pending ? { pendingKey: pending } : {}),
            ...keyExpiresOf(c.keyExpires),
            ...(isNum(c.sentKeyAt) ? { sentKeyAt: c.sentKeyAt } : {})
        };
    });

    const blocked = pickRecord<number>(raw.blocked, (id, at) => SNOWFLAKE.test(id) && isNum(at) ? at : null);
    const outgoing = pickRecord(raw.outgoing, (id, o) =>
        SNOWFLAKE.test(id) && isObj(o) && isNum(o.at) && isStr(o.channelId) ? { at: o.at, channelId: o.channelId } : null);
    const handled = pickRecord(raw.handled, (id, h) =>
        SNOWFLAKE.test(id) && isObj(h) && isNum(h.at) && ["accepted", "declined", "blocked", "stored"].includes(h.result) ? { at: h.at, result: h.result as HandledResult } : null);
    const channels = pickRecord<ChannelPrefs>(raw.channels, (id, p) => {
        if (!SNOWFLAKE.test(id) || !isObj(p)) return null;
        const target = normalizeTarget(p.target);
        return {
            encrypt: p.encrypt === true,
            ...(isNum(p.since) ? { since: p.since } : {}),
            ...(target ? { target } : {}),
            ...(typeof p.autoDecrypt === "boolean" ? { autoDecrypt: p.autoDecrypt } : {})
        };
    });

    return { v: 1, self, oldKeys, contacts, blocked, outgoing, handled, channels };
}

const DAY = 24 * 60 * 60 * 1000;

/** Keeps bookkeeping maps from growing forever. */
export function pruneVaultData(data: VaultData, now = Date.now()): void {
    for (const [id, o] of Object.entries(data.outgoing))
        if (now - o.at > 30 * DAY) delete data.outgoing[id];
    const handled = Object.entries(data.handled).sort((a, b) => b[1].at - a[1].at);
    for (const [i, [id, h]] of handled.entries())
        if (i >= 2000 || now - h.at > 180 * DAY) delete data.handled[id];
    for (const [id, p] of Object.entries(data.channels))
        if (!p.encrypt && !p.target && p.autoDecrypt == null) delete data.channels[id];
}
