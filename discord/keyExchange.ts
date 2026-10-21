/*
 * DcPgp – key exchange flow and contact/chat actions. Decisions come from core/ (tested);
 * this file only connects them to Discord messages, dialogs and the vault.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChannelStore, MessageActions, MessageStore } from "@webpack/common";

import {
    acceptPendingKey, applyKeyRefresh, blockUser, forgetContact, type IncomingKey, refreshContactKey, rejectPendingKey, setVerified, unblockUser,
    validateIncomingKey
} from "../core/contacts";
import {
    applyAccept, applyBlock, applyChangeLater, applyDecline, applyStoreResponse, buildKeyMessage, buildKeyUpdateMessage, canRequestAgain,
    decideIncoming, type IncomingContext, markHandled, markKeySent, pendingOffer, precheckIncoming, recordOutgoing
} from "../core/exchange";
import { type KeyMessageKind, parseContent } from "../core/format";
import { isoDay, needsOwnKeyUpdate } from "../core/keyLifetime";
import { setChannelEncryption } from "../core/menus";
import { safetyNumber } from "../core/safetyNumber";
import { confirmDialog, toastError, toastInfo, toastSuccess } from "../ui/dialogs";
import { askAcceptKey, askKeyChange, askResend, confirmRemoveContact, showSafetyNumber, warnMismatch } from "../ui/keyDialogs";
import { channelKind, dmPartnerId, ensureDmChannel, maxMessageLength, nameOf } from "./discordUtils";
import { logger, myId, S, saveVault, type Session, storeGuardTags } from "./state";

const errorText = (e: unknown) => e instanceof Error ? e.message : String(e);

/** Messages a dialog was already shown for in this session (also guards against duplicate events). */
const prompted = new Set<string>();
/** Key messages that arrived while locked; looked at once the vault is open. */
const queuedWhileLocked: any[] = [];
let chain: Promise<void> = Promise.resolve();
let unsubscribe: (() => void) | null = null;

async function sendProtocolMessage(channelId: string, content: string) {
    await MessageActions.sendMessage(channelId, { content, tts: false, invalidEmojis: [], validNonShortcutEmojis: [] }, true, {});
}

/** Sends our public key; `update`: as "Key update", because our key was extended since they got it. */
async function respondWithOwnKey(channelId: string, userId: string, name: string, o: { quiet?: boolean; update?: boolean; } = {}) {
    const session = S.session;
    if (!session) return;
    try {
        const own = session.data.self.publicKey;
        await sendProtocolMessage(channelId, o.update ? buildKeyUpdateMessage(own, maxMessageLength()) : buildKeyMessage("keyresp", own, maxMessageLength()));
        if (S.session === session) {
            markKeySent(session.data, userId);
            await saveVault();
        }
        if (!o.quiet) toastSuccess(o.update ? `Your updated key was sent to ${name}.` : `Your key was sent to ${name}.`);
    } catch (e) {
        logger.error("Sending the own key failed", e);
        toastError(`Sending your key to ${name} failed: ${errorText(e)}`);
    }
}

/** A known contact sent their key again: take over what is new in it, such as a later expiry. */
async function takeKeyUpdate(session: Session, authorId: string, name: string, incoming: IncomingKey): Promise<boolean> {
    const contact = session.data.contacts[authorId];
    if (!contact) return false;
    const refresh = await refreshContactKey(contact, incoming).catch(e => {
        logger.warn("Could not take over an updated key", e);
        return null;
    });
    if (S.session !== session) return false;
    // A request for their updated key, if we sent one, is answered either way.
    delete session.data.outgoing[authorId];
    if (!refresh) return false;
    applyKeyRefresh(session.data, authorId, refresh);
    toastInfo(refresh.keyExpires != null ? `${name}'s key was updated (valid until ${isoDay(refresh.keyExpires)}).` : `${name}'s key was updated.`);
    return true;
}

export async function requestKey(userId: string): Promise<void> {
    const session = S.session;
    const me = myId();
    if (!session || !me) return toastError("DcPgp is locked.");
    if (userId === me) return;
    const name = nameOf(userId);
    if (session.data.blocked[userId]) return toastError(`${name} is blocked. Unblock them first.`);
    if (!canRequestAgain(session.data, userId)
        && !await confirmDialog("Request already pending", `You already asked ${name} for their key today. Send it again anyway?`, "Send again", "Cancel"))
        return;
    try {
        const content = buildKeyMessage("keyreq", session.data.self.publicKey, maxMessageLength());
        const channelId = await ensureDmChannel(userId);
        await sendProtocolMessage(channelId, content);
        if (S.session !== session) return;
        recordOutgoing(session.data, userId, channelId);
        // The request carries our current key.
        markKeySent(session.data, userId);
        await saveVault();
        toastSuccess(`Key request sent to ${name}.`);
    } catch (e) {
        logger.error("Key request failed", e);
        toastError(`Key request to ${name} failed: ${errorText(e)}`);
    }
}

export async function openVerifyDialog(userId: string): Promise<void> {
    const session = S.session;
    const me = myId();
    const contact = session?.data.contacts[userId];
    if (!session || !me || !contact) return;
    if (contact.pendingKey) return reviewKeyChange(userId);
    const name = nameOf(userId);
    const number = safetyNumber({ fpr: session.data.self.fpr, userId: me }, { fpr: contact.fpr, userId });
    const choice = await showSafetyNumber(name, number, contact.verified);
    if (S.session !== session || choice === "later") return;
    setVerified(session.data, userId, choice === "match");
    await saveVault();
    if (choice === "match") toastSuccess(`${name} is verified.`);
    else await warnMismatch(name);
}

export async function reviewKeyChange(userId: string): Promise<void> {
    const session = S.session;
    const contact = session?.data.contacts[userId];
    if (!session || !contact?.pendingKey) return;
    const name = nameOf(userId);
    const choice = await askKeyChange(name, contact.fpr, contact.pendingKey.fpr);
    if (S.session !== session || choice === "later") return;
    if (choice === "accept") {
        acceptPendingKey(session.data, userId);
        await saveVault();
        await openVerifyDialog(userId);
    } else {
        rejectPendingKey(session.data, userId);
        await saveVault();
        toastInfo(`${name}'s new key was rejected. The previous key stays valid.`);
    }
}

/** A message that just arrived (dialogs decide), or a click on the card under it / in the lock menu (choice known). */
export type KeyMessageTrigger = "live" | "accept" | "decline" | "resend";

async function processKeyMessage(message: any, kind: KeyMessageKind, armoredKey: string, trigger: KeyMessageTrigger) {
    const session = S.session;
    const me = myId();
    const authorId: string | undefined = message?.author?.id;
    const live = trigger === "live";
    if (!session || !me || !authorId || (live && prompted.has(message.id))) return;

    const ctx: IncomingContext = {
        kind,
        messageId: message.id,
        authorId,
        myId: me,
        isDm: channelKind(ChannelStore.getChannel(message.channel_id)) === "dm"
    };
    const opts = { ignoreHandled: !live };
    const name = nameOf(authorId);
    const pre = precheckIncoming(ctx, session.data, opts);
    if (pre) {
        if (!live) toastInfo(pre.action === "ignore" && pre.reason === "blocked" ? `${name} is blocked.` : "This key message cannot be accepted.");
        return;
    }
    prompted.add(message.id);

    let incoming: IncomingKey;
    try {
        incoming = await validateIncomingKey(armoredKey);
    } catch (e) {
        if (S.session !== session) return;
        applyDecline(session.data, message.id);
        await saveVault();
        toastError(`Invalid key from ${name}: ${errorText(e)}`);
        return;
    }
    if (S.session !== session) return;

    const decision = decideIncoming(ctx, incoming.fpr, session.data, opts);
    switch (decision.action) {
        case "ignore":
            return;
        case "reject":
            applyDecline(session.data, message.id);
            await saveVault();
            toastError(decision.reason === "own-key"
                ? `${name} sent you your own key. Ignored.`
                : `The key from ${name} already belongs to ${decision.otherName}. Ignored.`);
            return;
        case "already-known": {
            const updated = await takeKeyUpdate(session, authorId, name, incoming);
            if (S.session !== session) return;
            markHandled(session.data, message.id, "stored");
            await saveVault();
            if (!live && !updated) toastInfo(`${name}'s key is already stored.`);
            return;
        }
        case "store-response":
        case "store-crossing": {
            if (trigger === "decline") {
                applyDecline(session.data, message.id);
                await saveVault();
                return;
            }
            const crossed = decision.action === "store-crossing";
            applyStoreResponse(session.data, authorId, name, incoming, message.id);
            await saveVault();
            // Their request crossed ours: they may not have our key yet, so answer it.
            if (crossed) await respondWithOwnKey(message.channel_id, authorId, name, { quiet: true });
            if (!live) return openVerifyDialog(authorId);
            // No forced modal: the answer may arrive while the user is busy elsewhere.
            toastSuccess(crossed
                ? `Your requests crossed: ${name}'s key is stored and yours is on its way. Verify? Use the lock menu in the chat.`
                : `Received ${name}'s key – verify it? Use the lock menu in the chat or right-click → DcPgp.`);
            return;
        }
        case "ask-resend": {
            const updated = await takeKeyUpdate(session, authorId, name, incoming);
            if (S.session !== session) return;
            if (trigger === "accept") {
                if (updated) await saveVault();
                else toastInfo(`${name}'s key is already stored.`);
                return;
            }
            const contact = session.data.contacts[authorId];
            // They have a copy of our key from before its last extension: answer without asking.
            const outdated = contact != null && needsOwnKeyUpdate(session.data.self, contact);
            const send = outdated || (live ? await askResend(name) : trigger === "resend");
            if (S.session !== session) return;
            markHandled(session.data, message.id, send ? "accepted" : "declined");
            await saveVault();
            if (send) await respondWithOwnKey(message.channel_id, authorId, name, { update: outdated });
            return;
        }
        case "ask-new": {
            const choice = live ? await askAcceptKey(name, incoming.fpr, kind) : trigger === "decline" ? "decline" : "accept";
            if (S.session !== session || choice === "later") return;
            if (choice === "decline") {
                applyDecline(session.data, message.id);
                await saveVault();
                return;
            }
            if (choice === "block") {
                applyBlock(session.data, authorId, message.id);
                await saveVault();
                toastInfo(`${name} blocked.`);
                return;
            }
            applyAccept(session.data, authorId, name, incoming, message.id);
            await saveVault();
            if (kind === "keyreq") await respondWithOwnKey(message.channel_id, authorId, name);
            await openVerifyDialog(authorId);
            return;
        }
        case "ask-changed": {
            const choice = await askKeyChange(name, decision.previousFpr, incoming.fpr);
            if (S.session !== session) return;
            if (choice === "accept") {
                applyAccept(session.data, authorId, name, incoming, message.id);
                await saveVault();
                if (kind === "keyreq") await respondWithOwnKey(message.channel_id, authorId, name);
                await openVerifyDialog(authorId);
            } else if (choice === "reject") {
                applyDecline(session.data, message.id);
                await saveVault();
            } else {
                applyChangeLater(session.data, authorId, incoming, message.id);
                await saveVault();
                toastInfo(`Encryption to ${name} is paused until you review the new key.`);
            }
            return;
        }
    }
}

/** Partners a key update is being sent to right now, so a burst of messages sends it once. */
const sendingUpdate = new Set<string>();

/**
 * After our own encrypted message in a 1:1 DM: if the partner still has a copy of our key from before its
 * last extension, the current one follows once. That way the update reaches the people we actually write to.
 */
async function sendKeyUpdateIfNeeded(message: any) {
    const session = S.session;
    if (!session || message?.author?.id == null || message.author.id !== myId()) return;
    const channel = ChannelStore.getChannel(message.channel_id);
    if (!channel || channelKind(channel) !== "dm") return;
    const partnerId = dmPartnerId(channel);
    const contact = partnerId ? session.data.contacts[partnerId] : undefined;
    if (!partnerId || !contact || !needsOwnKeyUpdate(session.data.self, contact) || sendingUpdate.has(partnerId)) return;
    sendingUpdate.add(partnerId);
    try {
        await respondWithOwnKey(message.channel_id, partnerId, nameOf(partnerId), { update: true, quiet: true });
    } finally {
        sendingUpdate.delete(partnerId);
    }
}

/** Called for every new message from the server (flux MESSAGE_CREATE). Cheap for normal messages. */
export function onMessageCreate(message: any) {
    const parsed = parseContent(message?.content);
    if (parsed.kind === "message") {
        sendKeyUpdateIfNeeded(message).catch(e => logger.error("Could not send the key update", e));
        return;
    }
    if (parsed.kind !== "keyreq" && parsed.kind !== "keyresp") return;
    if (!S.session) {
        if (queuedWhileLocked.length < 50) queuedWhileLocked.push(message);
        return;
    }
    const { kind, armoredKey } = parsed;
    // One dialog at a time.
    chain = chain
        .then(() => processKeyMessage(message, kind, armoredKey, "live"))
        .catch(e => logger.error("Could not process key message", e));
}

/** A click on the card under a key message or on "Accept key" in the lock menu. Works for old messages too. */
export function actOnKeyMessage(message: any, choice: Exclude<KeyMessageTrigger, "live">): Promise<void> {
    const parsed = parseContent(message?.content);
    if (parsed.kind !== "keyreq" && parsed.kind !== "keyresp") return Promise.resolve();
    if (!S.session) {
        toastError("DcPgp is locked.");
        return Promise.resolve();
    }
    const { kind, armoredKey } = parsed;
    chain = chain
        .then(() => processKeyMessage(message, kind, armoredKey, choice))
        .catch(e => logger.error("Could not process key message", e));
    return chain;
}

/** The newest unanswered key message from the partner among the loaded messages of the DM (for the lock menu). */
export function findPendingOffer(channelId: string, partnerId: string): any | null {
    const session = S.session;
    if (!session || session.data.contacts[partnerId] || session.data.blocked[partnerId]) return null;
    const candidates: { id: string; authorId: string; message: any; }[] = [];
    MessageStore.getMessages(channelId)?.forEach(m => {
        const kind = parseContent(m.content).kind;
        if ((kind === "keyreq" || kind === "keyresp") && m.author?.id === partnerId)
            candidates.push({ id: m.id, authorId: partnerId, message: m });
    });
    return pendingOffer(candidates, partnerId, session.data)?.message ?? null;
}

export type KeyCheck = { fpr: string; } | { error: string; };
const keyChecks = new Map<string, Promise<KeyCheck>>();

/** Parses an offered public key once. Public data, so the cache may outlive a lock. */
export function checkOfferedKey(armoredKey: string): Promise<KeyCheck> {
    let check = keyChecks.get(armoredKey);
    if (!check) {
        check = validateIncomingKey(armoredKey).then(k => ({ fpr: k.fpr }), e => ({ error: errorText(e) }));
        keyChecks.set(armoredKey, check);
        if (keyChecks.size > 100) keyChecks.delete(keyChecks.keys().next().value!);
    }
    return check;
}

export async function setChatEncrypted(channelId: string, on: boolean): Promise<void> {
    const session = S.session;
    if (!session) return toastError("DcPgp is locked.");
    setChannelEncryption(session.data, channelId, on);
    await saveVault();
    toastInfo(on ? "This chat is encrypted from now on." : "Encryption for this chat is switched off.");
}

export function toggleOneShot(channelId: string) {
    if (S.oneShot.has(channelId)) S.oneShot.delete(channelId);
    else S.oneShot.add(channelId);
    S.emit();
}

export async function blockContact(userId: string): Promise<void> {
    const session = S.session;
    if (!session) return;
    blockUser(session.data, userId);
    await saveVault();
    toastInfo(`${nameOf(userId)} blocked.`);
}

export async function unblockContact(userId: string): Promise<void> {
    const session = S.session;
    if (!session) return;
    unblockUser(session.data, userId);
    await saveVault();
    toastInfo(`${nameOf(userId)} unblocked.`);
}

/**
 * "Remove contact" from the lock menu or the user menu. channelId: the 1:1 DM to stop encrypting
 * (null if there is none). Old key messages stay handled and a block stays in place.
 */
export async function removeContactFlow(userId: string, channelId: string | null): Promise<void> {
    const session = S.session;
    if (!session) return toastError("DcPgp is locked.");
    const name = nameOf(userId);
    if (!await confirmRemoveContact(name) || S.session !== session) return;
    forgetContact(session.data, userId, channelId);
    if (channelId) S.oneShot.delete(channelId);
    // While locked, the send protection only knows encrypted chats from these tags.
    await storeGuardTags();
    // Saving also re-renders the lock menu and the messages of this chat.
    await saveVault();
    toastInfo(channelId ? `Contact ${name} removed – encryption in this chat is off.` : `Contact ${name} removed.`);
}

export function startKeyExchange() {
    unsubscribe ??= S.subscribe(() => {
        if (S.session && queuedWhileLocked.length)
            for (const message of queuedWhileLocked.splice(0)) onMessageCreate(message);
    });
}

export function stopKeyExchange() {
    unsubscribe?.();
    unsubscribe = null;
    queuedWhileLocked.length = 0;
    prompted.clear();
    sendingUpdate.clear();
}
