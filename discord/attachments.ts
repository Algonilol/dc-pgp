/*
 * DcPgp – encrypted attachments in 1:1 DMs. Discord uploads a file the moment it is attached, so DcPgp steps in
 * before that: the file is encrypted first, and only the encrypted copy is attached (neutral name, no preview).
 * The signed message lists the files' ids. On receiving, a file is downloaded from Discord's CDN, checked against
 * that list, decrypted and shown – in memory only, dropped when DcPgp locks. Decisions: core/attachments.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChannelStore, DraftType, FluxDispatcher, UploadAttachmentStore } from "@webpack/common";

import {
    attachmentId, attachStart, AUTO_OPEN_BYTES, checkUploadsForSend, encryptedFileName, formatSize, type PreviewKind, previewOf, readersKey, safeFileName
} from "../core/attachments";
import { missingReasonText } from "../core/menus";
import { decryptFileVerified, encryptFileSigned } from "../core/pgp";
import type { DecryptedView } from "../core/receive";
import { toastError, toastInfo } from "../ui/dialogs";
import { keysForMessage } from "./decrypt";
import { channelKind, planForChannel } from "./discordUtils";
import { Native } from "./native";
import { isChannelEncrypted, logger, myId, onLock, parsedKey, S } from "./state";

/** Uploads DcPgp encrypted, by their File: the id the message lists, and for whom. */
const encryptedFiles = new WeakMap<File, { id: string; readers: string; }>();
let active = false;
let interceptorInstalled = false;

const WEB_PLATFORM = 1;

function later(text: string, info = false) {
    setTimeout(() => {
        try {
            (info ? toastInfo : toastError)("DcPgp: " + text);
        } catch (e) {
            logger.error("Toast failed:", text, e);
        }
    }, 0);
}

const isOurs = (item: any) => item?.file instanceof File && encryptedFiles.has(item.file);

/** Whether Discord's upload object carries a file DcPgp encrypted. */
export function isEncryptedUpload(upload: any): boolean {
    return isOurs(upload?.item);
}

function needsEncryption(channelId: string): boolean {
    return isChannelEncrypted(channelId) || S.oneShot.has(channelId);
}

/** Flux interceptor: files attached in an encrypted chat. Returning true drops the action – nothing is uploaded. */
function interceptUploads(action: any): boolean {
    const type = action?.type;
    if (!active || (type !== "UPLOAD_ATTACHMENT_ADD_FILES" && type !== "UPLOAD_ATTACHMENT_SET_FILE")) return false;
    // An exception here would break Discord's dispatch, and letting the action through would upload the file.
    try {
        const { channelId, draftType } = action;
        const items: any[] = type === "UPLOAD_ATTACHMENT_ADD_FILES" ? action.files : [action.file];
        if (!Array.isArray(items) || !items.length || items.every(isOurs)) return false;
        const start = attachStart({
            encrypted: needsEncryption(channelId),
            phase: S.phase,
            dm: channelKind(ChannelStore.getChannel(channelId)) === "dm",
            channelMessage: draftType === DraftType.ChannelMessage,
            files: items.map(i => ({ size: Number(i?.file?.size ?? 0) })),
            alreadyAttached: type === "UPLOAD_ATTACHMENT_SET_FILE" ? 0 : UploadAttachmentStore.getUploads(channelId, draftType)?.length ?? 0
        });
        if (start.action === "keep") return false;
        if (start.action === "refuse") {
            later(start.message);
            return true;
        }
        if (type === "UPLOAD_ATTACHMENT_SET_FILE") {
            later("An encrypted attachment can't be replaced. Remove it and attach the new file.");
            return true;
        }
        void encryptAndAttach(channelId, draftType, items.map(i => i.file as File));
        return true;
    } catch (e) {
        try { logger.error("Attachment check failed – file not attached", e); } catch { }
        later("Checking the file failed – it was NOT attached.");
        return true;
    }
}

async function encryptAndAttach(channelId: string, draftType: unknown, files: File[]) {
    const session = S.session;
    try {
        if (!session || !myId()) throw new Error("DcPgp is locked.");
        const plan = planForChannel(ChannelStore.getChannel(channelId));
        if (plan.kind !== "dm") throw new Error("Encrypted attachments work in 1:1 DMs.");
        const missing = plan.missing[0];
        if (missing) throw new Error(`${missing.name} can't receive encrypted files right now: ${missingReasonText(missing.reason)}.`);
        if (!plan.readers.length) throw new Error("Nobody in this chat has a stored key.");

        const keys = [...await Promise.all(plan.readers.map(r => parsedKey(r.contact.publicKey))), session.ownPublic];
        const readers = readersKey(plan.readers.map(r => ({ userId: r.userId, fpr: r.contact.fpr })));
        const total = files.reduce((n, f) => n + f.size, 0);
        if (total > 4 * 1024 * 1024) later(`Encrypting ${files.length === 1 ? "the file" : `${files.length} files`} (${formatSize(total)}) …`, true);

        const first = UploadAttachmentStore.getUploads(channelId, draftType as any)?.length ?? 0;
        const items: any[] = [];
        for (const [i, file] of files.entries()) {
            const plain = new Uint8Array(await file.arrayBuffer());
            let sealed: Uint8Array;
            try {
                sealed = await encryptFileSigned(plain, safeFileName(file.name), keys, session.privateKey);
            } finally {
                plain.fill(0);
            }
            const encrypted = new File([sealed as Uint8Array<ArrayBuffer>], encryptedFileName(first + i), { type: "application/octet-stream" });
            encryptedFiles.set(encrypted, { id: await attachmentId(sealed), readers });
            // A fresh item: nothing from the original (clip data, origin) travels along.
            items.push({ file: encrypted, platform: WEB_PLATFORM, isThumbnail: false });
        }
        if (S.session !== session) throw new Error("DcPgp was locked while encrypting.");
        FluxDispatcher.dispatch({ type: "UPLOAD_ATTACHMENT_ADD_FILES", channelId, draftType, files: items, allowOptimization: false } as any);
        later(`${files.length === 1 ? "File" : `${files.length} files`} encrypted – shown as ${items.map(i => i.file.name).join(", ")}.`, true);
    } catch (e) {
        logger.warn("Encrypting an attachment failed", e);
        later(`${e instanceof Error ? e.message : String(e)} The file was NOT attached.`);
    }
}

/**
 * The files of the chat input's message about to be sent: all must be DcPgp's, encrypted for these readers.
 * Takes the original names and alt texts off Discord's upload objects. Returns the ids for the signed message.
 */
export function idsForSending(channelId: string, readers: string): { ids: string[]; } | { error: string; } {
    const uploads: any[] = UploadAttachmentStore.getUploads(channelId, DraftType.ChannelMessage) ?? [];
    const result = checkUploadsForSend(uploads.map(u => ({ encrypted: encryptedFiles.get(u?.item?.file) })), readers);
    if ("ids" in result) {
        for (const [i, u] of uploads.entries()) {
            u.filename = encryptedFileName(i);
            u.description = null;
            u.spoiler = false;
        }
    }
    return result;
}

// --- receiving --------------------------------------------------------------------------------------

export interface DiscordAttachment {
    id: string;
    filename: string;
    size: number;
    url: string;
}

export type OpenedFile =
    /** `note`: the file's own signature did not check out (the signed message still vouches for the file). */
    | { status: "ok"; name: string; size: number; kind: PreviewKind; url: string; blob: Blob; note?: string; }
    | { status: "error"; message: string; }
    /** Large: opened only on request. */
    | { status: "large"; size: number; };

/** Decrypted files of the session: blob URLs, revoked on lock. */
const opened = new Map<string, Promise<OpenedFile>>();
const urls = new Set<string>();

/**
 * Includes what the message's check says about its signer: on unlock a message can be decrypted before the
 * sender's key is stored, and once it is, the same content comes back checked – its files must be tried again.
 */
const cacheKey = (messageId: string, a: DiscordAttachment, view: DecryptedView) =>
    `${messageId}:${a.id}:${view.contentId}:${view.signerFpr ?? ""}:${view.trust === "failed" ? "failed" : ""}`;

/** Downloads, checks and decrypts one encrypted file of a decrypted message. */
export function openAttachment(message: { id: string; channel_id: string; author?: { id: string; }; }, view: DecryptedView, a: DiscordAttachment, force = false): Promise<OpenedFile> {
    const key = cacheKey(message.id, a, view);
    const cached = opened.get(key);
    if (cached) return cached;
    if (!force && a.size > AUTO_OPEN_BYTES) return Promise.resolve({ status: "large", size: a.size });
    const session = S.session;
    const job = (async (): Promise<OpenedFile> => {
        try {
            const authorId = message.author?.id;
            if (!session || !authorId) return { status: "error", message: "DcPgp is locked." };
            // The message's signature vouches for its files: without a checked signer, none is opened.
            if (!view.signerFpr || view.trust === "failed")
                return { status: "error", message: "The message's signature could not be checked, so its files are not opened." };
            const bytes = new Uint8Array(await Native.fetchAttachment(a.url));
            if (!view.meta?.attachments?.includes(await attachmentId(bytes)))
                return { status: "error", message: "This file is not one the message was signed with. It was swapped or added later." };
            const keys = await keysForMessage(authorId, message.channel_id);
            const verification = authorId === myId()
                ? keys.ownPublic.map(k => k.key)
                : keys.author ? [keys.author.current.key, ...keys.author.history.map(h => h.key)] : [];
            const result = await decryptFileVerified(bytes, keys.decryptionKeys, verification);
            if (S.session !== session) return { status: "error", message: "DcPgp was locked." };
            // The signed list already binds exactly this file to the message; the file's own signature is a second check.
            const sig = result.signature;
            let note: string | undefined;
            if (sig.status !== "valid" || sig.signerFingerprint !== view.signerFpr) {
                const why = sig.status !== "valid" ? `${sig.status}${sig.error ? ": " + sig.error : ""}` : "made by another key";
                logger.warn("File signature check: " + JSON.stringify({ file: a.id, status: sig.status, keyId: sig.keyId, signer: sig.signerFingerprint, expected: view.signerFpr, created: sig.created, error: sig.error }));
                note = `The file's own signature didn't check out (${why.slice(0, 140)}). The signed message vouches for it.`;
            }
            const name = safeFileName(result.filename);
            const preview = previewOf(name);
            const blob = new Blob([result.data as Uint8Array<ArrayBuffer>], { type: preview.mime });
            const url = URL.createObjectURL(blob);
            urls.add(url);
            return { status: "ok", name, size: result.data.length, kind: preview.kind, url, blob, ...(note ? { note } : {}) };
        } catch (e) {
            logger.warn("Opening an attachment failed", a.id, (e as Error)?.message);
            return { status: "error", message: "This encrypted file could not be opened (damaged or not for you)." };
        }
    })();
    opened.set(key, job);
    return job;
}

/** Saves a decrypted file where the user chooses. */
export async function saveOpenedFile(file: Extract<OpenedFile, { status: "ok"; }>): Promise<string | null> {
    const bytes = new Uint8Array(await file.blob.arrayBuffer());
    try {
        return await Native.saveBinaryFile(file.name, bytes);
    } finally {
        bytes.fill(0);
    }
}

function forgetOpened() {
    for (const url of urls) URL.revokeObjectURL(url);
    urls.clear();
    opened.clear();
}

onLock(forgetOpened);

/** Idempotent; returns a problem if files could not be protected. */
export function installAttachmentProtection(): string[] {
    active = true;
    if (interceptorInstalled) return [];
    const dispatcher = FluxDispatcher as any;
    if (typeof dispatcher.addInterceptor !== "function")
        return ["Discord's dispatcher has no interceptors – files can't be encrypted, and attaching one in an encrypted chat uploads it unencrypted."];
    dispatcher.addInterceptor(interceptUploads);
    interceptorInstalled = true;
    return [];
}

export function uninstallAttachmentProtection() {
    active = false;
    forgetOpened();
    const list = (FluxDispatcher as any)._interceptors;
    if (Array.isArray(list)) {
        const i = list.indexOf(interceptUploads);
        if (i >= 0) list.splice(i, 1);
        interceptorInstalled = list.includes(interceptUploads);
    }
}
