/*
 * DcPgp – key exchange decisions (request, response, key change). Pure: no Discord imports.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { addOrReplaceContact, classifyIncomingKey, type IncomingKey, markKeyChange } from "./contacts";
import { buildKeyMessageContent, buildKeyUpdateContent, discordLength, type KeyMessageKind } from "./format";
import type { MenuPhase } from "./menus";
import type { Contact, HandledResult, VaultData } from "./model";

export const REQUEST_COOLDOWN_MS = 24 * 60 * 60 * 1000;

export interface IncomingContext {
    kind: KeyMessageKind;
    messageId: string;
    authorId: string;
    myId: string;
    /** Key messages are only accepted in 1:1 DMs, so the sender is unambiguous. */
    isDm: boolean;
}

export type IgnoreReason = "not-dm" | "own-message" | "handled" | "blocked";

export type IncomingDecision =
    | { action: "ignore"; reason: IgnoreReason; }
    | { action: "reject"; reason: "own-key"; }
    | { action: "reject"; reason: "belongs-to-other"; otherName: string; }
    /** Someone without a stored key offers one: ask the user. */
    | { action: "ask-new"; }
    /** Answer to our own request with a new key: store without asking. */
    | { action: "store-response"; }
    /** Their request crossed ours: we asked for exactly this key, so store it and answer with ours. */
    | { action: "store-crossing"; }
    /** A contact asks again although we already have their (same) key: offer to resend ours. */
    | { action: "ask-resend"; }
    /** Response with the key we already have. */
    | { action: "already-known"; }
    /** A different key than the stored one: the user must decide, encryption pauses meanwhile. */
    | { action: "ask-changed"; previousFpr: string; };

export interface IncomingOptions {
    /** A click on a key message: an earlier decision about it may be revised. */
    ignoreHandled?: boolean;
}

/** Checks that need no key parsing. Returns null if the message has to be looked at. */
export function precheckIncoming(ctx: IncomingContext, data: VaultData, opts: IncomingOptions = {}): IncomingDecision | null {
    if (!ctx.isDm) return { action: "ignore", reason: "not-dm" };
    if (ctx.authorId === ctx.myId) return { action: "ignore", reason: "own-message" };
    if (!opts.ignoreHandled && data.handled[ctx.messageId]) return { action: "ignore", reason: "handled" };
    if (data.blocked[ctx.authorId]) return { action: "ignore", reason: "blocked" };
    return null;
}

export function decideIncoming(ctx: IncomingContext, fpr: string, data: VaultData, opts: IncomingOptions = {}): IncomingDecision {
    const pre = precheckIncoming(ctx, data, opts);
    if (pre) return pre;
    const cls = classifyIncomingKey(fpr, ctx.authorId, data);
    switch (cls.state) {
        case "own-key": return { action: "reject", reason: "own-key" };
        case "belongs-to-other": return { action: "reject", reason: "belongs-to-other", otherName: cls.otherName };
        case "changed": return { action: "ask-changed", previousFpr: cls.previousFpr };
        case "same": return ctx.kind === "keyreq" ? { action: "ask-resend" } : { action: "already-known" };
        case "new":
            if (!data.outgoing[ctx.authorId]) return { action: "ask-new" };
            return ctx.kind === "keyresp" ? { action: "store-response" } : { action: "store-crossing" };
    }
}

export interface KeyMessageRef {
    id: string;
    authorId: string;
}

/** Snowflakes are decimal strings without leading zeros: longer means newer. */
function isNewer(a: string, b: string): boolean {
    return a.length !== b.length ? a.length > b.length : a > b;
}

/**
 * The newest key message from the partner that nobody has decided on yet, so the lock menu can offer
 * "Accept key" – e.g. after the dialog was closed with "Later" or the message arrived while Discord was closed.
 */
export function pendingOffer<T extends KeyMessageRef>(messages: Iterable<T>, partnerId: string, data: VaultData): T | null {
    if (data.contacts[partnerId] || data.blocked[partnerId]) return null;
    let newest: T | null = null;
    for (const m of messages)
        if (m.authorId === partnerId && !data.handled[m.id] && (!newest || isNewer(m.id, newest.id))) newest = m;
    return newest;
}

export type KeyCardActionId = "accept" | "decline" | "verify" | "resend" | "review" | "unlock" | "setup";

export interface KeyCardModel {
    tone: "info" | "ok" | "warning" | "danger";
    text: string;
    /** Fingerprint of the offered key, shown where the user decides about it. */
    fpr?: string;
    actions: { id: KeyCardActionId; label: string; }[];
}

export interface KeyCardInput {
    phase: MenuPhase;
    kind: KeyMessageKind;
    messageId: string;
    authorId: string;
    authorName: string;
    myId: string | null;
    isDm: boolean;
    /** The offered key: its fingerprint, or why it is invalid. Undefined while it is being checked. */
    check?: { fpr: string; } | { error: string; };
    /** The open vault; null while locked. */
    data: VaultData | null;
}

/** What the card that replaces the raw key block in the chat says and offers. */
export function keyCardModel(i: KeyCardInput): KeyCardModel {
    const what = i.kind === "keyreq" ? "Key request" : "Key";
    const name = i.authorName;
    if (i.myId != null && i.authorId === i.myId)
        return { tone: "info", text: i.kind === "keyreq" ? "Your key request (DcPgp)" : "Your public key (DcPgp)", actions: [] };
    if (i.phase === "nosetup")
        return { tone: "info", text: `${what} from ${name} – set up DcPgp to chat encrypted.`, actions: [{ id: "setup", label: "Set up" }] };
    if (i.phase !== "unlocked" || !i.data || i.myId == null)
        return { tone: "info", text: `${what} from ${name} – unlock DcPgp to answer.`, actions: i.phase === "locked" ? [{ id: "unlock", label: "Unlock" }] : [] };
    if (!i.isDm) return { tone: "info", text: `${what} from ${name} – keys are only accepted in direct messages.`, actions: [] };
    if (!i.check) return { tone: "info", text: `${what} from ${name} – checking …`, actions: [] };
    if ("error" in i.check) return { tone: "danger", text: `Invalid key from ${name}: ${i.check.error}`, actions: [] };

    const { fpr } = i.check;
    const ctx: IncomingContext = { kind: i.kind, messageId: i.messageId, authorId: i.authorId, myId: i.myId, isDm: true };
    const d = decideIncoming(ctx, fpr, i.data, { ignoreHandled: true });
    const handled = i.data.handled[i.messageId]?.result;
    const contact = i.data.contacts[i.authorId];
    switch (d.action) {
        case "ignore":
            return { tone: "info", text: `${what} from ${name} – ${name} is blocked.`, actions: [] };
        case "reject":
            return {
                tone: "danger",
                text: d.reason === "own-key" ? `${name} sent you your own key – ignored.` : `This key already belongs to ${d.otherName} – ignored.`,
                actions: []
            };
        case "already-known":
        case "ask-resend": {
            const actions: KeyCardModel["actions"] = [];
            if (!contact?.verified) actions.push({ id: "verify", label: "Compare safety number" });
            if (d.action === "ask-resend" && handled !== "accepted") actions.push({ id: "resend", label: "Send my key" });
            return { tone: "ok", text: `${name}'s key is stored${contact?.verified ? " and verified" : ""}.`, actions };
        }
        case "ask-changed":
            return {
                tone: handled ? "info" : "warning",
                text: contact?.history.some(h => h.fpr === fpr)
                    ? `An older key of ${name} that has since been replaced.`
                    : `${name} sent a different key than the stored one.`,
                fpr,
                actions: [{ id: "review", label: "Review …" }]
            };
        case "ask-new":
        case "store-response":
        case "store-crossing":
            if (handled === "declined" || handled === "blocked")
                return { tone: "info", text: `${what} from ${name} – declined.`, fpr, actions: [{ id: "accept", label: "Accept anyway" }] };
            if (handled)
                return { tone: "info", text: `${what} from ${name} – the contact has been removed since.`, fpr, actions: [{ id: "accept", label: "Accept again" }] };
            return {
                tone: "info",
                text: i.kind === "keyreq" ? `${name} wants to chat encrypted with you.` : `${name} sent you their key.`,
                fpr,
                actions: [{ id: "accept", label: "Accept" }, { id: "decline", label: "Decline" }]
            };
    }
}

/** Stores the key (unverified) and marks the message as dealt with. */
export function applyAccept(data: VaultData, authorId: string, name: string, incoming: IncomingKey, messageId: string, now = Date.now()): Contact {
    const contact = addOrReplaceContact(data, authorId, name, incoming, now);
    delete data.outgoing[authorId];
    data.handled[messageId] = { at: now, result: "accepted" };
    return contact;
}

export function applyStoreResponse(data: VaultData, authorId: string, name: string, incoming: IncomingKey, messageId: string, now = Date.now()): Contact {
    const requestedAt = data.outgoing[authorId]?.at;
    const contact = addOrReplaceContact(data, authorId, name, incoming, now);
    // Our request carried our key as it was then.
    if (requestedAt != null) contact.sentKeyAt = Math.max(contact.sentKeyAt ?? 0, requestedAt);
    delete data.outgoing[authorId];
    data.handled[messageId] = { at: now, result: "stored" };
    return contact;
}

export function markHandled(data: VaultData, messageId: string, result: HandledResult, now = Date.now()) {
    data.handled[messageId] = { at: now, result };
}

/** A contact received our current key (in a request, a response or an update). */
export function markKeySent(data: VaultData, userId: string, now = Date.now()) {
    const c = data.contacts[userId];
    if (c) c.sentKeyAt = now;
}

export function applyDecline(data: VaultData, messageId: string, now = Date.now()) {
    markHandled(data, messageId, "declined", now);
}

export function applyBlock(data: VaultData, authorId: string, messageId: string, now = Date.now()) {
    data.blocked[authorId] = now;
    delete data.outgoing[authorId];
    data.handled[messageId] = { at: now, result: "blocked" };
}

/** Undecided key change: keep the old key, remember the new one, pause encryption to this person. */
export function applyChangeLater(data: VaultData, authorId: string, incoming: IncomingKey, messageId: string, now = Date.now()) {
    markKeyChange(data, authorId, incoming, messageId, now);
    data.handled[messageId] = { at: now, result: "declined" };
}

export function canRequestAgain(data: VaultData, userId: string, now = Date.now()): boolean {
    const pending = data.outgoing[userId];
    return !pending || now - pending.at >= REQUEST_COOLDOWN_MS;
}

export function recordOutgoing(data: VaultData, userId: string, channelId: string, now = Date.now()) {
    data.outgoing[userId] = { at: now, channelId };
}

export class KeyMessageTooLongError extends Error {
    constructor(public readonly length: number, public readonly limit: number) {
        super(`Your public key does not fit into a Discord message (${length} of ${limit} characters). A Curve25519 key fits.`);
        this.name = "KeyMessageTooLongError";
    }
}

function fitKeyMessage(content: string, limit: number): string {
    const length = discordLength(content);
    if (length > limit) throw new KeyMessageTooLongError(length, limit);
    return content;
}

export function buildKeyMessage(kind: KeyMessageKind, ownPublicKey: string, limit: number): string {
    return fitKeyMessage(buildKeyMessageContent(kind, ownPublicKey), limit);
}

export function buildKeyUpdateMessage(ownPublicKey: string, limit: number): string {
    return fitKeyMessage(buildKeyUpdateContent(ownPublicKey), limit);
}
