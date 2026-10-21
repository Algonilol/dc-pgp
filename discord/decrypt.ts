/*
 * DcPgp – decrypting incoming messages: queue and plaintext cache (memory only, cleared on lock),
 * the flux hooks for new and edited messages, and the check of our own sent messages.
 * Plaintext never goes into Discord's message objects; the UI reads it from here.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChannelStore, MessageActions, useEffect, useReducer } from "@webpack/common";

import { type EchoResult, effectiveAutoDecrypt, ownEchoProblems, ownEchoVerdict } from "../core/display";
import { parseContent, type ParsedContent, snowflakeToMs } from "../core/format";
import { setChannelAutoDecrypt } from "../core/menus";
import { keyHasKeyId, NotForUsError } from "../core/pgp";
import { type DecryptedView, decryptForDisplay, noteCopy, type ReceiveKeys } from "../core/receive";
import { settings } from "../settings";
import { confirmDialog, toastError } from "../ui/dialogs";
import { nameOf } from "./discordUtils";
import { noteHookProblem } from "./sendHooks";
import { isChannelEncrypted, logger, myId, onLock, parsedKey, S, saveVault } from "./state";

export type DecryptStatus = "pending" | "ok" | "not-for-us" | "error" | "locked";

export interface DecryptEntry {
    status: DecryptStatus;
    view?: DecryptedView;
    error?: string;
}

/** The fields we need; fits Discord's message records and raw flux payloads alike. */
export interface MessageLike {
    id: string;
    channel_id: string;
    content?: string;
    author?: { id: string; };
    editedTimestamp?: unknown;
    edited_timestamp?: unknown;
    /** "SENDING" / "SEND_FAILED" for the local copy of a message that is still being sent. */
    state?: string;
}

interface CacheItem {
    entry: DecryptEntry;
    /** Results from an older generation (contacts changed since) stay visible until the fresh one is ready. */
    gen: number;
    refreshing?: boolean;
}

const MAX_ENTRIES = 1000;
const CONCURRENCY = 2;
const LOCKED: DecryptEntry = { status: "locked" };

const cache = new Map<string, CacheItem>();
/** Block hash → the earliest message shown with it; see noteCopy. */
const firstCopies = new Map<string, string>();
const subscribers = new Map<string, Set<() => void>>();
const queue: Array<() => Promise<void>> = [];
let running = 0;
let generation = 0;
let contactsSignature = "";

function fnv1a(text: string): string {
    let h1 = 0x811c9dc5, h2 = 0x01000193;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 0x01000193);
        h2 = Math.imul(h2 ^ c, 0x5bd1e995);
    }
    return (h1 >>> 0).toString(36) + (h2 >>> 0).toString(36);
}

const entryKey = (messageId: string, armored: string) => messageId + ":" + fnv1a(armored);

function notify(key: string) {
    const subs = subscribers.get(key);
    if (subs) for (const fn of [...subs]) fn();
}

function notifyAll() {
    for (const key of [...subscribers.keys()]) notify(key);
}

function subscribeEntry(key: string, fn: () => void) {
    let set = subscribers.get(key);
    if (!set) subscribers.set(key, set = new Set());
    set.add(fn);
    return () => {
        set!.delete(fn);
        if (!set!.size) subscribers.delete(key);
    };
}

function pump() {
    while (running < CONCURRENCY && queue.length) {
        const job = queue.shift()!;
        running++;
        job().finally(() => {
            running--;
            setTimeout(pump, 0);
        });
    }
}

function remember(key: string, item: CacheItem) {
    cache.delete(key);
    cache.set(key, item);
    while (cache.size > MAX_ENTRIES) cache.delete(cache.keys().next().value!);
}

async function receiveKeysFor(authorId: string, channelId: string): Promise<ReceiveKeys> {
    const session = S.session!;
    const contact = session.data.contacts[authorId] ?? null;
    const author = contact ? {
        name: contact.name,
        verified: contact.verified,
        current: { fpr: contact.fpr, key: await parsedKey(contact.publicKey) },
        history: await Promise.all(contact.history.map(async h => ({ fpr: h.fpr, key: await parsedKey(h.publicKey), replacedAt: h.replacedAt })))
    } : null;

    const contactKeys = await Promise.all(Object.values(session.data.contacts).map(async c => ({ c, key: await parsedKey(c.publicKey).catch(() => null) })));

    return {
        decryptionKeys: [session.privateKey, ...session.oldPrivate],
        ownPublic: session.ownPublicList,
        author,
        authorName: nameOf(authorId, ChannelStore.getChannel(channelId)?.guild_id),
        findContactByKeyId(keyId) {
            const hit = contactKeys.find(x => x.key && keyHasKeyId(x.key, keyId));
            return hit ? { userId: hit.c.userId, name: hit.c.name } : null;
        }
    };
}

function toMs(value: unknown): number | null {
    if (value == null || value === "") return null;
    const t = typeof value === "number" ? value
        : typeof value === "string" ? Date.parse(value)
            : Number((value as { valueOf(): unknown; }).valueOf());
    return Number.isFinite(t) ? t : null;
}

/** Discord's time for the message (or its latest edit); compared with the signed send time. */
function discordTime(message: MessageLike): number {
    return toMs(message.editedTimestamp) ?? toMs(message.edited_timestamp)
        ?? (/^\d{1,25}$/.test(message.id) ? snowflakeToMs(message.id) : Date.now());
}

function enqueue(key: string, message: MessageLike, armored: string) {
    const session = S.session;
    const me = myId();
    const authorId = message.author!.id;
    const channelId = message.channel_id;
    const time = discordTime(message);

    queue.push(async () => {
        if (!me || !session || S.session !== session) return;
        const gen = generation;
        let entry: DecryptEntry;
        try {
            const keys = await receiveKeysFor(authorId, channelId);
            entry = { status: "ok", view: await decryptForDisplay(armored, { authorId, channelId, myId: me, discordTimeMs: time }, keys) };
        } catch (e) {
            if (e instanceof NotForUsError) entry = { status: "not-for-us" };
            else {
                logger.warn("Decryption failed", message.id, (e as Error)?.message);
                entry = { status: "error", error: String((e as Error)?.message ?? e) };
            }
        }
        if (S.session !== session) return;
        remember(key, { entry, gen });
        notify(key);
    });
    pump();
}

/** Returns the cached result or starts decrypting; subscribers of the entry are notified when it is ready. */
export function getDecryption(message: MessageLike, armored: string): DecryptEntry {
    if (!S.session || !message.author?.id) return LOCKED;
    const key = entryKey(message.id, armored);
    const cached = cache.get(key);
    if (cached) {
        if (cached.gen !== generation && cached.entry.status !== "pending" && !cached.refreshing) {
            cached.refreshing = true;
            enqueue(key, message, armored);
        }
        return cached.entry;
    }
    const entry: DecryptEntry = { status: "pending" };
    remember(key, { entry, gen: generation });
    enqueue(key, message, armored);
    return entry;
}

/** Synchronous lookup without starting work (used by the edit helper). */
export function peekDecryption(messageId: string, armored: string): DecryptEntry | undefined {
    return cache.get(entryKey(messageId, armored))?.entry;
}

/** Resolves once the message is decrypted, or as "locked" if the vault was locked meanwhile. */
export function whenDecrypted(message: MessageLike, armored: string): Promise<DecryptEntry> {
    const first = getDecryption(message, armored);
    if (first.status !== "pending") return Promise.resolve(first);
    const key = entryKey(message.id, armored);
    return new Promise(resolve => {
        const unsubscribe = subscribeEntry(key, () => {
            const now = cache.get(key)?.entry ?? LOCKED;
            if (now.status === "pending") return;
            unsubscribe();
            resolve(now);
        });
    });
}

/** React hook: the decryption of a message, re-rendering when it is ready. Pass null to skip. */
export function useDecryption(message: MessageLike, armored: string | null): DecryptEntry | null {
    const [, force] = useReducer((x: number) => x + 1, 0);
    const entry = armored ? getDecryption(message, armored) : null;
    const key = armored ? entryKey(message.id, armored) : null;
    useEffect(() => {
        if (!key) return;
        const unsubscribe = subscribeEntry(key, force);
        // The result may have arrived between render and subscribe.
        if (cache.get(key)?.entry !== entry) force();
        return unsubscribe;
    }, [key]);
    return entry;
}

/**
 * Whether an earlier message already carried this block (replayed or re-posted). The local copy of a
 * message that is still being sent is left out: it carries the same block as the server's copy.
 */
export function isRepeatedBlock(message: MessageLike, armored: string): boolean {
    if (message.state === "SENDING" || message.state === "SEND_FAILED") return false;
    const check = noteCopy(firstCopies, fnv1a(armored), message.id);
    // The message noted first is the later copy after all: show it again, with the warning. Not during this render.
    if (check.demoted) {
        const key = entryKey(check.demoted, armored);
        setTimeout(() => notify(key), 0);
    }
    return check.repeated;
}

export function revealMessage(messageId: string) {
    S.revealed.add(messageId);
    S.emit();
}

export async function setChatAutoDecrypt(channelId: string, on: boolean): Promise<void> {
    const session = S.session;
    if (!session) return toastError("DcPgp is locked.");
    setChannelAutoDecrypt(session.data, channelId, on, settings.store.autoDecrypt);
    await saveVault();
}

function autoDecryptIn(channelId: string): boolean {
    return effectiveAutoDecrypt(settings.store.autoDecrypt, S.session?.data.channels[channelId]);
}

/** Starts decrypting early so the plaintext is ready when Discord renders the message. */
function warm(message: MessageLike, parsed: ParsedContent) {
    if (parsed.kind === "message" && S.session && autoDecryptIn(message.channel_id))
        getDecryption(message, parsed.armored);
}

// --- check of our own sent messages -------------------------------------------------------------

interface PendingEcho {
    mustBeEncrypted: boolean;
    at: number;
}

/** Optimistic copies of messages sent from this client, by nonce. */
const pendingEcho = new Map<string, PendingEcho>();
const ECHO_TTL_MS = 10 * 60_000;
const MAX_PENDING = 200;

function prunePending(now: number) {
    for (const [nonce, p] of pendingEcho) {
        if (now - p.at <= ECHO_TTL_MS && pendingEcho.size <= MAX_PENDING) break;
        pendingEcho.delete(nonce);
    }
}

function echoResult(entry: DecryptEntry): EchoResult {
    switch (entry.status) {
        case "ok": return { status: "ok", view: entry.view! };
        case "error": return { status: "error", error: entry.error };
        default: return { status: entry.status };
    }
}

async function reportLeak(message: MessageLike) {
    noteHookProblem("A message from an encrypted chat reached Discord unencrypted.");
    const remove = await confirmDialog(
        "Message sent unencrypted!",
        "Your message in an encrypted chat reached Discord as plaintext – the send protection failed (probably after a Discord or Vencord update). Don't write anything in encrypted chats until this is fixed. Delete it on Discord now? Anyone who has already seen it (also via a notification) still knows it.",
        "Delete now",
        "Keep",
        true
    );
    if (remove) MessageActions.deleteMessage(message.channel_id, message.id);
}

async function verifyOwn(message: MessageLike, armored: string, what: string) {
    const entry = await whenDecrypted(message, armored);
    const problems = ownEchoProblems(echoResult(entry), message.channel_id);
    if (!problems.length) return;
    logger.error(`Check of your ${what} failed`, message.id, problems);
    toastError(`Check of your ${what}: ${problems[0]}`);
}

async function checkOwnEcho(message: MessageLike, parsed: ParsedContent, sent: PendingEcho | undefined) {
    const verdict = ownEchoVerdict({
        sentHere: sent != null,
        mustBeEncrypted: sent?.mustBeEncrypted ?? false,
        kind: parsed.kind,
        hasText: (message.content ?? "").trim().length > 0
    });
    if (verdict === "leak") await reportLeak(message);
    else if (verdict === "verify" && parsed.kind === "message" && S.session) await verifyOwn(message, parsed.armored, "sent message");
}

/** The server's copy of a message we sent has a new id; reuse what the optimistic copy already decrypted. */
function adoptOptimistic(nonce: string, message: MessageLike, parsed: ParsedContent) {
    if (parsed.kind !== "message") return;
    const from = cache.get(entryKey(nonce, parsed.armored));
    const to = entryKey(message.id, parsed.armored);
    if (from && from.entry.status !== "pending" && !cache.has(to)) remember(to, { entry: from.entry, gen: from.gen });
}

/** Flux MESSAGE_CREATE, also for optimistic copies of messages we are sending. */
export function handleMessageCreate(message: any, optimistic: boolean) {
    if (typeof message?.id !== "string" || typeof message.channel_id !== "string") return;
    const parsed = parseContent(message.content);
    const me = myId();
    const own = me != null && message.author?.id === me;
    const nonce = message.nonce != null ? String(message.nonce) : null;

    if (own && nonce) {
        if (optimistic) {
            const now = Date.now();
            prunePending(now);
            const channelId: string = message.channel_id;
            pendingEcho.set(nonce, {
                mustBeEncrypted: isChannelEncrypted(channelId) || S.oneShot.has(channelId) || parsed.kind === "message",
                at: now
            });
        } else {
            const sent = pendingEcho.get(nonce);
            pendingEcho.delete(nonce);
            if (sent) adoptOptimistic(nonce, message, parsed);
            checkOwnEcho(message, parsed, sent).catch(e => logger.error("Checking an own message failed", e));
        }
    }
    warm(message, parsed);
}

/** Flux MESSAGE_UPDATE: edits get a new content, so a new cache entry; our own edits are checked too. */
export function handleMessageUpdate(message: any) {
    if (typeof message?.id !== "string" || typeof message.channel_id !== "string" || typeof message.content !== "string") return;
    const parsed = parseContent(message.content);
    warm(message, parsed);
    const me = myId();
    if (me && message.author?.id === me && message.edited_timestamp && parsed.kind === "message" && S.session)
        verifyOwn(message, parsed.armored, "edit").catch(e => logger.error("Checking an own message failed", e));
}

// --- lifecycle ------------------------------------------------------------------------------------

/** Trust labels depend on the contacts (verified, key changes): re-evaluate shown messages when they change. */
function onStateChange() {
    const data = S.session?.data;
    if (!data) return;
    const signature = Object.values(data.contacts)
        // keyExpires changes with an updated key: messages signed after the old expiry are checked again.
        .map(c => `${c.userId}:${c.fpr}:${c.verified ? 1 : 0}:${c.pendingKey?.fpr ?? ""}:${c.history.length}:${c.keyExpires ?? ""}`)
        .sort()
        .join("|");
    if (signature === contactsSignature) return;
    contactsSignature = signature;
    generation++;
    notifyAll();
}

function clearPlaintext() {
    cache.clear();
    firstCopies.clear();
    queue.length = 0;
    contactsSignature = "";
    notifyAll();
}

onLock(clearPlaintext);

let unsubscribeState: (() => void) | null = null;

export function startDecryption() {
    unsubscribeState ??= S.subscribe(onStateChange);
}

export function stopDecryption() {
    unsubscribeState?.();
    unsubscribeState = null;
    pendingEcho.clear();
    clearPlaintext();
}
