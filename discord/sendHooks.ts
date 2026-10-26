/*
 * DcPgp – send protection: encrypting pre-send hook (first listener), emergency brake around
 * Discord's own send/edit functions, and the draft filter. Everything here fails closed.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { addMessagePreSendListener, type MessageObject, type MessageSendListener, removeMessagePreSendListener, type SendMessageOptions, type SendMessageProps } from "@api/MessageEvents";
import { plugins } from "@api/PluginManager";
import type { Channel } from "@vencord/discord-types";
import { findByProps } from "@webpack";
import { ChannelStore, DraftStore, MessageStore } from "@webpack/common";

import { isEncryptedContent } from "../core/format";
import { checkEdit, checkOutgoing, filterDraftState, SILENT_PREFIX } from "../core/guard";
import { encryptForChannel, type MissingReason, TooLongError } from "../core/send";
import { toastError } from "../ui/dialogs";
import { maxMessageLength, planForChannel } from "./discordUtils";
import { isChannelEncrypted, logger, myId, parsedKey, S } from "./state";

const PLUGIN_NAME = "DcPgp";
const ENCRYPT_TIMEOUT_MS = 20_000;
const CANCEL = { cancel: true };

/** Content our hook produced for a message object; the brake makes sure exactly this goes out. */
const expected = new WeakMap<object, string>();
/** Message objects that passed our hook. A composer send that did not is a broken hook. */
const seenByHook = new WeakSet<object>();

let active = false;
let preSendInstalled = false;

export function safeToast(text: string) {
    try {
        toastError("DcPgp: " + text);
    } catch (e) {
        logger.error("Toast failed:", text, e);
    }
}

export function cancel(text: string) {
    safeToast(text);
    return CANCEL;
}

/** Why a message or edit must not go out; shown to the user. */
export class Refusal extends Error { }

/** Records what our hook made of a message object: the brake then lets exactly this out. */
export function expectContent(msg: object, content: string) {
    expected.set(msg, content);
}

function missingText(m: { name: string; reason: MissingReason; }): string {
    switch (m.reason) {
        case "no-key": return `No key of ${m.name} is stored.`;
        case "key-changed": return `${m.name} has a new key that is not confirmed yet.`;
        case "key-expired": return `${m.name}'s key has expired. Request their updated key in the lock menu.`;
        case "blocked": return `${m.name} is blocked.`;
    }
}

function intendedTime(options: SendMessageOptions | undefined): number {
    const scheduled = options?.scheduledTimestamp as any;
    if (scheduled != null) {
        const t = new Date(scheduled).getTime();
        if (Number.isFinite(t)) return t;
    }
    return Date.now();
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("Encryption timed out")), ms);
        promise.then(
            value => { clearTimeout(timer); resolve(value); },
            error => { clearTimeout(timer); reject(error); }
        );
    });
}

/**
 * Encrypts a text for a chat after every check a send needs; throws Refusal when it must not go out.
 * Shared by sending and editing, so both encrypt for exactly the same readers.
 */
export async function encryptForChat(channelId: string, channel: Channel | null | undefined, text: string, time: number, maxLength: number): Promise<string> {
    const session = S.session;
    const me = myId();
    if (S.phase !== "unlocked" || !session || !me) throw new Refusal("This chat is encrypted, but DcPgp is locked.");

    const plan = planForChannel(channel ?? ChannelStore.getChannel(channelId));
    if (plan.unsupported) throw new Refusal("DcPgp cannot encrypt in this type of chat.");
    if (plan.visibilityUnknown) throw new Refusal("DcPgp cannot check who can see this channel (Discord update?).");
    if (plan.kind === "dm" && plan.missing.length) throw new Refusal(missingText(plan.missing[0]));
    if (!plan.readers.length) throw new Refusal("Nobody in this chat has a stored key.");

    const recipients = await Promise.all(plan.readers.map(async r => ({ userId: r.userId, key: await parsedKey(r.contact.publicKey) })));
    let encrypted: string;
    try {
        encrypted = await withTimeout(encryptForChannel({
            text,
            senderId: me,
            channelId,
            recipients,
            ownPublic: session.ownPublic,
            signer: session.privateKey,
            time,
            maxLength
        }), ENCRYPT_TIMEOUT_MS);
    } catch (e) {
        if (e instanceof TooLongError) throw new Refusal(e.message);
        throw e;
    }
    if (S.session !== session) throw new Refusal("DcPgp was locked while encrypting.");
    return encrypted;
}

async function encryptOutgoing(channelId: string, msg: MessageObject, options: SendMessageOptions | undefined, props: SendMessageProps | undefined) {
    const oneShot = S.oneShot.has(channelId);
    if (!oneShot && !isChannelEncrypted(channelId)) return;

    if (S.phase !== "unlocked" || !S.session || !myId())
        return cancel("This chat is encrypted, but DcPgp is locked. Message NOT sent.");
    if (options?.alsoForwardToChannelId)
        return cancel("\"Also send to channel\" does not work with encrypted messages. Message NOT sent.");
    if (props?.hasAttachments)
        return cancel("Attachments are not encrypted yet. Message NOT sent.");

    const raw = typeof msg.content === "string" ? msg.content : "";
    const silent = raw.startsWith(SILENT_PREFIX);
    const text = silent ? raw.slice(SILENT_PREFIX.length) : raw;
    if (!text.trim()) return;

    let encrypted: string;
    try {
        encrypted = await encryptForChat(channelId, props?.channel, text, intendedTime(options), maxMessageLength() - (silent ? SILENT_PREFIX.length : 0));
    } catch (e) {
        if (e instanceof Refusal) return cancel(`${e.message} Message NOT sent.`);
        throw e;
    }

    const finalContent = (silent ? SILENT_PREFIX : "") + encrypted;
    msg.content = finalContent;
    msg.tts = false;
    msg.validNonShortcutEmojis = [];
    msg.invalidEmojis = [];
    expected.set(msg, finalContent);
    if (oneShot) {
        S.oneShot.delete(channelId);
        S.emit();
    }
}

/** Must never throw: Vencord would log the error and send the message anyway (fail-open). */
const preSend: MessageSendListener = async (channelId, msg, options, props) => {
    try {
        seenByHook.add(msg);
        return await encryptOutgoing(channelId, msg, options, props);
    } catch (e) {
        try { logger.error("Send hook: error, message not sent", e); } catch { }
        safeToast("Encryption failed – message NOT sent.");
        return CANCEL;
    }
};

/** Registers our listener and moves every other plugin's listener behind it, so none sees plaintext. */
function installPreSend() {
    if (preSendInstalled) return;
    addMessagePreSendListener(preSend);
    preSendInstalled = true;
    for (const p of Object.values(plugins)) {
        if (!p?.started || p.name === PLUGIN_NAME) continue;
        for (const fn of [p.onBeforeMessageSend, (p as any).preSend]) {
            if (typeof fn === "function" && fn !== preSend && removeMessagePreSendListener(fn))
                addMessagePreSendListener(fn);
        }
    }
}

function isComposer(options: any): boolean {
    const location = String(options?.location ?? "");
    return location === "chat_input" || location === "chat input";
}

/** Marks the send protection as broken; the lock menu then refuses to switch encryption on. */
export function noteHookProblem(text: string) {
    if (!S.hookHealthy) return;
    S.hookHealthy = false;
    S.hookProblem = text;
    logger.error(text);
    S.emit();
}

type AnyFn = (...args: any[]) => any;
interface Wrapped { obj: any; key: string; original: AnyFn; wrapper: AnyFn; }
const wrapped = new Map<string, Wrapped>();

function wrap(id: string, obj: any, key: string, make: (original: AnyFn) => AnyFn): boolean {
    if (wrapped.has(id)) return true;
    const original = obj?.[key];
    if (typeof original !== "function") return false;
    const wrapper = make(original);
    obj[key] = wrapper;
    wrapped.set(id, { obj, key, original, wrapper });
    return true;
}

function unwrapAll() {
    for (const [id, w] of wrapped) {
        // If something wrapped us afterwards we stay in the chain as an inactive pass-through.
        if (w.obj[w.key] !== w.wrapper) continue;
        w.obj[w.key] = w.original;
        wrapped.delete(id);
    }
}

const guardedSend = (original: AnyFn) => function (this: unknown, ...args: any[]) {
    if (!active) return original.apply(this, args);
    const [channelId, message, options] = args;
    let block: string | null;
    try {
        const isObj = typeof message === "object" && message !== null;
        const content = typeof message?.content === "string" ? message.content : "";
        const fromComposer = isComposer(options);
        const seen = isObj && seenByHook.has(message);
        if (fromComposer && !seen) noteHookProblem("A message from the chat input did not pass the send hook.");
        const verdict = checkOutgoing({
            encrypted: isChannelEncrypted(channelId),
            content,
            expected: isObj ? expected.get(message) : undefined,
            allowedPlain: false,
            hasPoll: options?.poll != null,
            fromComposer,
            seenByHook: seen
        });
        block = verdict.ok ? null : verdict.message;
    } catch (e) {
        logger.error("Emergency brake: check failed", e);
        block = "Internal error in the send check. Message NOT sent.";
    }
    if (block) {
        safeToast(block);
        return Promise.resolve();
    }
    return original.apply(this, args);
};

const guardedEdit = (original: AnyFn) => function (this: unknown, ...args: any[]) {
    if (!active) return original.apply(this, args);
    const [channelId, messageId, message] = args;
    let block: string | null;
    try {
        const isObj = typeof message === "object" && message !== null;
        const originalContent = MessageStore.getMessage(channelId, messageId)?.content;
        const verdict = checkEdit({
            mustEncrypt: isChannelEncrypted(channelId) || isEncryptedContent(originalContent),
            content: typeof message?.content === "string" ? message.content : "",
            originalContent,
            expected: isObj ? expected.get(message) : undefined,
            allowedPlain: false
        });
        block = verdict.ok ? null : verdict.message;
    } catch (e) {
        logger.error("Emergency brake: checking the edit failed", e);
        block = "Internal error in the edit check. Change NOT saved.";
    }
    if (block) {
        safeToast(block);
        return Promise.resolve();
    }
    return original.apply(this, args);
};

const filteredDraftState = (original: AnyFn) => function (this: unknown) {
    const state = original.call(this);
    if (!active) return state;
    try {
        return filterDraftState(state, channelId => isChannelEncrypted(channelId));
    } catch (e) {
        logger.error("Draft filter failed – no drafts are saved", e);
        return {};
    }
};

/** Idempotent; returns problems that leave a protection layer inactive. */
export function installSendProtection(): string[] {
    const problems: string[] = [];
    active = true;
    installPreSend();

    let actions: any = null;
    if (!wrapped.has("send") || !wrapped.has("edit")) {
        try {
            actions = findByProps("_sendMessage", "editMessage");
        } catch (e) {
            logger.warn("MessageActions not found", e);
        }
    }
    if (!wrap("send", actions, "_sendMessage", guardedSend))
        problems.push("Discord's send function not found – emergency brake for sending inactive.");
    if (!wrap("edit", actions, "editMessage", guardedEdit))
        problems.push("Discord's edit function not found – emergency brake for edits inactive.");

    const draftsWereFiltered = wrapped.has("drafts");
    if (wrap("drafts", DraftStore, "getState", filteredDraftState)) {
        if (!draftsWereFiltered) {
            try { (DraftStore as any).asyncPersist?.(); } catch { }
        }
    } else {
        problems.push("DraftStore not found – draft filter inactive.");
    }
    return problems;
}

export function uninstallSendProtection() {
    active = false;
    if (preSendInstalled) {
        removeMessagePreSendListener(preSend);
        preSendInstalled = false;
    }
    unwrapAll();
}
