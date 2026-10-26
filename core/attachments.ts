/*
 * DcPgp – encrypted attachments: the neutral name on Discord, the ids that bind each file to its signed
 * message, which files are opened and how they are shown. Pure decisions; the Discord side is discord/attachments.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { asBufferSource, toBase64 } from "./bytes";
import { MAX_ATTACHMENTS } from "./format";
import type { MenuPhase } from "./menus";

export { MAX_ATTACHMENTS };

/** Encrypting reads the whole file into memory. */
export const MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024;
/** Larger files wait for a click before they are downloaded and decrypted. */
export const AUTO_OPEN_BYTES = 25 * 1024 * 1024;

const ENCRYPTED_NAME = /^dcpgp-\d{1,2}\.pgp$/;

/** What Discord sees as the file name: nothing about the original. */
export function encryptedFileName(index: number): string {
    return `dcpgp-${index + 1}.pgp`;
}

export function isEncryptedFileName(name: string | null | undefined): boolean {
    return typeof name === "string" && ENCRYPTED_NAME.test(name);
}

/** 128 bits of SHA-256 over the encrypted file, base64url. The signed message lists these, so no file can be swapped in. */
export async function attachmentId(encrypted: Uint8Array): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(encrypted)));
    return toBase64(digest.subarray(0, 16)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The file name from inside the encryption, safe to show and to suggest when saving: no path, no control
 * characters, and no direction marks that make "invoice‮fdp.exe" look like "invoiceexe.pdf".
 */
export function safeFileName(name: string | null | undefined): string {
    const base = String(name ?? "").split(/[\\/]/).pop() ?? "";
    const clean = base.replace(/[\u0000-\u001f\u007f<>:"|?*‎‏‪-‮⁦-⁩]/g, "").trim().replace(/^\.+/, "").slice(0, 120);
    return clean || "attachment";
}

export type PreviewKind = "image" | "video" | "audio" | "file";

/**
 * Shown inline only for formats the browser renders as media, chosen by the name – never by the content.
 * SVG, HTML and everything else is offered as a file to save.
 */
const PREVIEW: Record<string, [PreviewKind, string]> = {
    png: ["image", "image/png"],
    jpg: ["image", "image/jpeg"],
    jpeg: ["image", "image/jpeg"],
    gif: ["image", "image/gif"],
    webp: ["image", "image/webp"],
    avif: ["image", "image/avif"],
    mp4: ["video", "video/mp4"],
    webm: ["video", "video/webm"],
    mp3: ["audio", "audio/mpeg"],
    ogg: ["audio", "audio/ogg"],
    opus: ["audio", "audio/ogg"],
    wav: ["audio", "audio/wav"],
    m4a: ["audio", "audio/mp4"],
    flac: ["audio", "audio/flac"]
};

export function previewOf(name: string): { kind: PreviewKind; mime: string; } {
    const ext = /\.([a-z0-9]{1,5})$/i.exec(name)?.[1]?.toLowerCase() ?? "";
    const known = PREVIEW[ext];
    return known ? { kind: known[0], mime: known[1] } : { kind: "file", mime: "application/octet-stream" };
}

export function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Who a file was encrypted for: if this changes before sending, the file must be attached again. */
export function readersKey(readers: { userId: string; fpr: string; }[]): string {
    return readers.map(r => `${r.userId}:${r.fpr}`).sort().join("|");
}

export type AttachStart =
    /** Not an encrypted chat: Discord's own upload. */
    | { action: "keep"; }
    /** Encrypt first; Discord only ever gets the encrypted file. */
    | { action: "encrypt"; }
    /** Not attached at all: Discord would upload it right away, unencrypted. */
    | { action: "refuse"; message: string; };

export interface AttachInput {
    /** The chat is encrypted, or "next message only" is armed. */
    encrypted: boolean;
    phase: MenuPhase;
    /** 1:1 DMs only for now. */
    dm: boolean;
    /** The chat input's draft (not a thread's first message, a slash command and the like). */
    channelMessage: boolean;
    files: { size: number; }[];
    alreadyAttached: number;
}

/** Discord uploads a file the moment it is attached, so the decision has to come before that. */
export function attachStart(i: AttachInput): AttachStart {
    if (!i.encrypted) return { action: "keep" };
    if (i.phase !== "unlocked") return { action: "refuse", message: "This chat is encrypted, but DcPgp is locked. The file was NOT attached." };
    if (!i.dm || !i.channelMessage) return { action: "refuse", message: "Encrypted attachments work in 1:1 DMs. The file was NOT attached." };
    if (i.alreadyAttached + i.files.length > MAX_ATTACHMENTS) return { action: "refuse", message: `At most ${MAX_ATTACHMENTS} files per message. The file was NOT attached.` };
    if (i.files.some(f => f.size > MAX_ATTACHMENT_BYTES))
        return { action: "refuse", message: `DcPgp encrypts files up to ${formatSize(MAX_ATTACHMENT_BYTES)}. The file was NOT attached.` };
    if (i.files.some(f => f.size === 0)) return { action: "refuse", message: "An empty file cannot be attached." };
    return { action: "encrypt" };
}

export interface UploadForSend {
    /** Set when DcPgp encrypted this upload: its id and for whom. */
    encrypted?: { id: string; readers: string; };
}

/**
 * The uploads of a message about to be sent in an encrypted chat: all must be DcPgp's, encrypted for
 * exactly the chat's current readers. Returns their ids in order, or why the message must not go out.
 */
export function checkUploadsForSend(uploads: UploadForSend[], readers: string): { ids: string[]; } | { error: string; } {
    if (uploads.length > MAX_ATTACHMENTS) return { error: `At most ${MAX_ATTACHMENTS} files per message.` };
    const ids: string[] = [];
    for (const u of uploads) {
        // Toasts are cut after a line or two: what to do comes first.
        if (!u.encrypted) return { error: "Remove the file and attach it again – it was added before this chat was encrypted, so Discord has it unencrypted." };
        if (u.encrypted.readers !== readers) return { error: "Remove the files and attach them again – the keys in this chat changed after you attached them." };
        ids.push(u.encrypted.id);
    }
    return { ids };
}

export type AttachmentProblem = "not-listed" | "missing" | "unsigned";

/** Encrypted files of a message compared with its signed list (ids of the files that arrived). */
export function compareWithList(listed: string[] | undefined, arrived: string[]): { problems: AttachmentProblem[]; } {
    const problems: AttachmentProblem[] = [];
    const list = listed ?? [];
    if (arrived.some(id => !list.includes(id))) problems.push("not-listed");
    if (list.some(id => !arrived.includes(id))) problems.push("missing");
    return { problems };
}
