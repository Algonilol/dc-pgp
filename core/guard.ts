/*
 * DcPgp – pure decision logic of the emergency brake (outgoing messages/edits) and the draft filter.
 * No Discord imports, so it can be tested in Node.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { isEncryptedContent, isProtocolContent } from "./format";

export const SILENT_PREFIX = "@silent ";

/** Discord strips a leading "@silent " after our hook, so content is compared without it. */
export function stripSilent(content: string): string {
    return content.startsWith(SILENT_PREFIX) ? content.slice(SILENT_PREFIX.length) : content;
}

export type Verdict =
    | { ok: true; }
    | { ok: false; reason: "modified" | "poll" | "hook-missing" | "plaintext"; message: string; };

const OK: Verdict = { ok: true };

export interface OutgoingCheck {
    /** The channel requires encryption (open vault or, while locked, the chat guard). */
    encrypted: boolean;
    content: string;
    /** Content our send hook produced for exactly this message object, if any. */
    expected?: string;
    /** The user explicitly chose to send this one message unencrypted. */
    allowedPlain: boolean;
    hasPoll: boolean;
    /** The send comes from the chat input, where our hook must have run first. */
    fromComposer: boolean;
    seenByHook: boolean;
}

/** In encrypted chats only dcpgp/1 content may leave; everything else is blocked. */
export function checkOutgoing(c: OutgoingCheck): Verdict {
    if (c.expected !== undefined && stripSilent(c.content) !== stripSilent(c.expected))
        return { ok: false, reason: "modified", message: "Another plugin changed the encrypted message afterwards. It was NOT sent." };
    if (!c.encrypted || c.allowedPlain) return OK;
    if (c.hasPoll)
        return { ok: false, reason: "poll", message: "Polls are not encrypted and are blocked in encrypted chats." };
    if (!c.content.trim()) return OK;
    if (c.expected !== undefined || isProtocolContent(c.content)) return OK;
    if (c.fromComposer && !c.seenByHook)
        return { ok: false, reason: "hook-missing", message: "The send protection did not run (probably after a Discord update). The message was NOT sent. Please update Vencord." };
    return { ok: false, reason: "plaintext", message: "This chat is encrypted, but the message is not. It was NOT sent." };
}

export interface EditCheck {
    /** Channel is encrypted or the edited message itself was encrypted. */
    mustEncrypt: boolean;
    content: string;
    originalContent?: string;
    expected?: string;
    allowedPlain: boolean;
}

export function checkEdit(c: EditCheck): Verdict {
    if (c.expected !== undefined && stripSilent(c.content) !== stripSilent(c.expected))
        return { ok: false, reason: "modified", message: "Another plugin changed the encrypted edit. It was NOT saved." };
    if (!c.mustEncrypt || c.allowedPlain) return OK;
    if (!c.content.trim()) return OK;
    if (c.originalContent !== undefined && c.content === c.originalContent) return OK;
    if (c.expected !== undefined || isEncryptedContent(c.content)) return OK;
    return { ok: false, reason: "plaintext", message: "In encrypted chats, edits must be encrypted. The change was NOT saved." };
}

/**
 * Drafts are persisted to disk via DraftStore.getState() ({ userId: { channelId: { draftType: draft } } }).
 * Returns the same state with every encrypted channel left out; the in-memory drafts stay untouched.
 */
export function filterDraftState<T>(state: T, isEncrypted: (channelId: string) => boolean): T {
    if (!state || typeof state !== "object") return state;
    let changed = false;
    const out: Record<string, unknown> = {};
    for (const [userId, channels] of Object.entries(state as Record<string, unknown>)) {
        if (!channels || typeof channels !== "object") {
            out[userId] = channels;
            continue;
        }
        const kept: Record<string, unknown> = {};
        for (const [channelId, drafts] of Object.entries(channels as Record<string, unknown>)) {
            if (isEncrypted(channelId)) changed = true;
            else kept[channelId] = drafts;
        }
        out[userId] = kept;
    }
    return (changed ? out : state) as T;
}
