/*
 * DcPgp – editing encrypted messages. Starting an edit puts the plaintext into Discord's edit box instead of
 * the PGP block (Discord keeps it in memory only; the box is closed when DcPgp locks), and saving encrypts the
 * new text for the same chat. Everything here fails closed; decisions: core/edit.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { addMessagePreEditListener, type MessageEditListener, type MessageObject, removeMessagePreEditListener } from "@api/MessageEvents";
import { plugins } from "@api/PluginManager";
import { EditMessageStore, FluxDispatcher, MessageActions, MessageStore } from "@webpack/common";

import { editSave, editStart } from "../core/edit";
import { parseContent } from "../core/format";
import { getDecryption, peekDecryption, whenDecrypted } from "./decrypt";
import { maxMessageLength } from "./discordUtils";
import { cancel, encryptForChat, expectContent, Refusal, safeToast } from "./sendHooks";
import { isChannelEncrypted, logger, onLock, S } from "./state";

const PLUGIN_NAME = "DcPgp";
const CANCEL = { cancel: true };

/** Edits that got our plaintext, by channel (Discord edits one message per channel at a time). */
const prefilled = new Map<string, string>();
let active = false;
let preEditInstalled = false;
let interceptorInstalled = false;

/** Flux interceptor: MESSAGE_START_EDIT gets the plaintext instead of the PGP block. Returning true drops the action. */
function interceptStartEdit(action: any): boolean {
    if (!active || action?.type !== "MESSAGE_START_EDIT") return false;
    // An exception here would break Discord's dispatch: never let one out.
    try {
        const { channelId, messageId, content, source } = action;
        const parsed = parseContent(content);
        if (parsed.kind !== "message") return false;
        const message = MessageStore.getMessage(channelId, messageId);
        const entry = message ? getDecryption(message, parsed.armored) : undefined;
        const start = editStart({ encrypted: true, phase: S.phase, decryption: entry && { status: entry.status, text: entry.view?.text } });
        switch (start.action) {
            case "plaintext":
                action.content = start.text;
                prefilled.set(channelId, messageId);
                return false;
            case "wait":
                if (message) {
                    whenDecrypted(message, parsed.armored)
                        .then(done => { if (done.status !== "locked") MessageActions.startEditMessage(channelId, messageId, content, source); })
                        .catch(e => logger.error("Edit start: decryption failed", e));
                }
                return true;
            case "refuse":
                setTimeout(() => safeToast(start.message), 0);
                return true;
            default:
                return false;
        }
    } catch (e) {
        try { logger.error("Edit start: check failed – no edit box", e); } catch { }
        return true;
    }
}

async function encryptEdit(channelId: string, messageId: string, msg: MessageObject) {
    const originalContent = MessageStore.getMessage(channelId, messageId)?.content ?? "";
    const parsed = parseContent(originalContent);
    const text = typeof msg.content === "string" ? msg.content : "";
    const previous = parsed.kind === "message" ? peekDecryption(messageId, parsed.armored) : undefined;
    const decision = editSave({
        mustEncrypt: isChannelEncrypted(channelId) || parsed.kind === "message",
        phase: S.phase,
        text,
        previousText: previous?.status === "ok" ? previous.view?.text : undefined
    });
    switch (decision.action) {
        case "pass":
            return;
        case "refuse":
            throw new Refusal(decision.message);
        case "unchanged":
            // Discord saves nothing when the content equals the message's: no "(edited)" for nothing.
            msg.content = originalContent;
            return;
        case "encrypt": {
            const encrypted = await encryptForChat(channelId, null, text, Date.now(), maxMessageLength());
            msg.content = encrypted;
            expectContent(msg, encrypted);
        }
    }
}

/** Must never throw: Vencord would log the error and save the edit anyway (fail-open). */
const preEdit: MessageEditListener = async (channelId, messageId, msg) => {
    try {
        await encryptEdit(channelId, messageId, msg);
    } catch (e) {
        if (e instanceof Refusal) return cancel(`${e.message} The change was NOT saved.`);
        try { logger.error("Edit hook: error, change not saved", e); } catch { }
        safeToast("Encryption failed – the change was NOT saved.");
        return CANCEL;
    }
};

/** Closes edit boxes that hold our plaintext. */
function closePrefilledEdits() {
    for (const [channelId, messageId] of prefilled) {
        try {
            if (EditMessageStore.isEditing(channelId, messageId)) (MessageActions as any).endEditMessage(channelId);
        } catch (e) {
            logger.warn("Could not close an edit box", e);
        }
    }
    prefilled.clear();
}

onLock(closePrefilledEdits);

/** Idempotent; returns problems that leave editing unprotected or inconvenient. */
export function installEditProtection(): string[] {
    const problems: string[] = [];
    active = true;
    if (!preEditInstalled) {
        addMessagePreEditListener(preEdit);
        preEditInstalled = true;
        // Every other plugin's edit listener goes behind ours, so none sees plaintext.
        for (const p of Object.values(plugins)) {
            if (!p?.started || p.name === PLUGIN_NAME) continue;
            const fn = p.onBeforeMessageEdit;
            if (typeof fn === "function" && fn !== preEdit && removeMessagePreEditListener(fn)) addMessagePreEditListener(fn);
        }
    }
    if (!interceptorInstalled) {
        const dispatcher = FluxDispatcher as any;
        if (typeof dispatcher.addInterceptor === "function") {
            dispatcher.addInterceptor(interceptStartEdit);
            interceptorInstalled = true;
        } else {
            problems.push("Discord's dispatcher has no interceptors – editing an encrypted message shows its PGP block.");
        }
    }
    return problems;
}

export function uninstallEditProtection() {
    active = false;
    closePrefilledEdits();
    if (preEditInstalled) {
        removeMessagePreEditListener(preEdit);
        preEditInstalled = false;
    }
    // Discord has no removeInterceptor; an inactive interceptor that is left behind does nothing.
    const list = (FluxDispatcher as any)._interceptors;
    if (Array.isArray(list)) {
        const i = list.indexOf(interceptStartEdit);
        if (i >= 0) list.splice(i, 1);
        interceptorInstalled = list.includes(interceptStartEdit);
    }
}
