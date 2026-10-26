/*
 * DcPgp – the dcpgp/1 wire format: message and key-exchange content, signed metadata inside the encryption
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { fromUtf8, randomUrlSafe, utf8, utf8Length } from "./bytes";

export const PROTOCOL = "dcpgp/1";

/**
 * Parsing only looks for "dcpgp/1" (and "keyreq"/"keyresp") in the first line, so other clients may word it
 * differently. The send brake, though, only lets out content exactly as this version builds it (core/guard.ts).
 */
export const MESSAGE_HINT = "-# 🔒 Encrypted message · dcpgp/1";
export const KEYREQ_HINT = "-# 🔑 Key request · dcpgp/1 keyreq";
export const KEYRESP_HINT = "-# 🔑 Key response · dcpgp/1 keyresp";
/** An extended own key travels as a "keyresp", so clients that only know requests and responses keep working. */
export const KEYUPD_HINT = "-# 🔑 Key update · dcpgp/1 keyresp";
/** Where to get DcPgp: a key request points people without the plugin there. */
export const PROJECT_URL = "https://github.com/Algonilol/dc-pgp";

const FENCE = "```";
const PAD_BLOCK = 64;
const META_PREFIX = "\n-- dcpgp/1;";
const MAX_CONTENT_SCAN = 25_000;
const SNOWFLAKE = /^\d{1,25}$/;
const MAX_RECIPIENT_IDS = 200;
/** Attachment ids: 128 bits of SHA-256 over the encrypted file, base64url (core/attachments.ts). */
const ATTACHMENT_ID = /^[A-Za-z0-9_-]{22}$/;
/** Discord's limit per message. */
export const MAX_ATTACHMENTS = 10;

const MESSAGE_BLOCK = /-----BEGIN PGP MESSAGE-----\r?\n[\s\S]+?\r?\n-----END PGP MESSAGE-----/;
const KEY_BLOCK = /-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n[\s\S]+?\r?\n-----END PGP PUBLIC KEY BLOCK-----/;

export type KeyMessageKind = "keyreq" | "keyresp";

export type ParsedContent =
    | { kind: "message"; armored: string; }
    | { kind: KeyMessageKind; armoredKey: string; }
    | { kind: "none"; };

const NONE: ParsedContent = { kind: "none" };

export function buildMessageContent(armored: string): string {
    return `${MESSAGE_HINT}\n${FENCE}\n${armored.trim()}\n${FENCE}`;
}

export function buildKeyMessageContent(kind: KeyMessageKind, armoredPublicKey: string): string {
    const hint = kind === "keyreq" ? KEYREQ_HINT : KEYRESP_HINT;
    // In angle brackets, Discord shows the link without a preview card under the message.
    const text = kind === "keyreq"
        ? `I'd like to chat with you end-to-end encrypted with DcPgp, a Vencord plugin. Get it here: <${PROJECT_URL}> – without it, you can ignore this message.`
        : "I accepted your key request. From now on we can chat encrypted.";
    return `${hint}\n${text}\n${FENCE}\n${armoredPublicKey.trim()}\n${FENCE}`;
}

export function buildKeyUpdateContent(armoredPublicKey: string): string {
    return `${KEYUPD_HINT}\nMy DcPgp key was extended. DcPgp takes the update over automatically.\n${FENCE}\n${armoredPublicKey.trim()}\n${FENCE}`;
}

/** Classifies a Discord message content without trusting any of it. */
export function parseContent(content: string | null | undefined): ParsedContent {
    if (!content || content.length > MAX_CONTENT_SCAN || !content.includes(PROTOCOL)) return NONE;
    const firstLine = content.trimStart().split("\n", 1)[0];
    if (!firstLine.includes(PROTOCOL)) return NONE;

    const keyKind: KeyMessageKind | null = /\bkeyreq\b/.test(firstLine) ? "keyreq" : /\bkeyresp\b/.test(firstLine) ? "keyresp" : null;
    if (keyKind) {
        const m = content.match(KEY_BLOCK);
        return m ? { kind: keyKind, armoredKey: m[0].replace(/\r\n/g, "\n") } : NONE;
    }

    const m = content.match(MESSAGE_BLOCK);
    return m ? { kind: "message", armored: m[0].replace(/\r\n/g, "\n") } : NONE;
}

export function isEncryptedContent(content: string | null | undefined): boolean {
    return parseContent(content).kind === "message";
}

export function isProtocolContent(content: string | null | undefined): boolean {
    return parseContent(content).kind !== "none";
}

export interface InnerMeta {
    sender: string;
    channel: string;
    recipients: string[];
    /** Intended send time in ms since epoch. */
    time: number;
    /** Ids of the encrypted attachments that belong to this message, in order. */
    attachments?: string[];
}

/** Plaintext plus a signed metadata line, padded to a multiple of 64 bytes. */
export function buildInner(text: string, meta: InnerMeta): Uint8Array {
    for (const id of [meta.sender, meta.channel, ...meta.recipients])
        if (!SNOWFLAKE.test(id)) throw new Error("Invalid Discord ID: " + id);
    const attachments = meta.attachments ?? [];
    if (attachments.length > MAX_ATTACHMENTS || !attachments.every(a => ATTACHMENT_ID.test(a))) throw new Error("Invalid attachment list");
    const files = attachments.length ? `a=${attachments.join(",")};` : "";
    const head = `${text}${META_PREFIX}s=${meta.sender};c=${meta.channel};r=${meta.recipients.join(",")};t=${Math.floor(meta.time)};${files}p=`;
    const len = utf8Length(head);
    const pad = (PAD_BLOCK - (len % PAD_BLOCK)) % PAD_BLOCK;
    return utf8(head + randomUrlSafe(pad));
}

export interface ParsedInner {
    text: string;
    meta: InnerMeta | null;
    /** Set when a metadata line exists but is malformed. */
    metaError?: string;
}

export function parseInner(bytes: Uint8Array): ParsedInner {
    const all = fromUtf8(bytes);
    const idx = all.lastIndexOf(META_PREFIX);
    if (idx < 0) return { text: all, meta: null };

    const text = all.slice(0, idx);
    const fields: Record<string, string> = Object.create(null);
    for (const part of all.slice(idx + META_PREFIX.length).split(";")) {
        const eq = part.indexOf("=");
        if (eq > 0) fields[part.slice(0, eq)] = part.slice(eq + 1);
    }

    const recipients = fields.r ? fields.r.split(",") : [];
    const attachments = fields.a ? fields.a.split(",") : [];
    const time = Number(fields.t);
    const valid = SNOWFLAKE.test(fields.s ?? "")
        && SNOWFLAKE.test(fields.c ?? "")
        && recipients.length <= MAX_RECIPIENT_IDS
        && recipients.every(r => SNOWFLAKE.test(r))
        && attachments.length <= MAX_ATTACHMENTS
        && attachments.every(a => ATTACHMENT_ID.test(a))
        && Number.isSafeInteger(time) && time >= 0;
    if (!valid) return { text, meta: null, metaError: "metadata damaged" };

    return { text, meta: { sender: fields.s, channel: fields.c, recipients, time, ...(attachments.length ? { attachments } : {}) } };
}

const DISCORD_EPOCH = 1420070400000n;

export function snowflakeToMs(id: string): number {
    return Number((BigInt(id) >> 22n) + DISCORD_EPOCH);
}

/** Discord's (server) time of a message id, or null if it is not a snowflake. */
export function snowflakeTime(id: string | null | undefined): number | null {
    return id && SNOWFLAKE.test(id) ? snowflakeToMs(id) : null;
}

export type FindingLevel = "error" | "warning" | "info";

export interface Finding {
    level: FindingLevel;
    code: string;
    text: string;
}

export interface ReceiveContext {
    authorId: string;
    channelId: string;
    myId: string;
    /** Discord's timestamp for the message (or for the latest edit). */
    discordTimeMs: number;
}

export const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

/** Compares the signed metadata with what Discord says about the message. */
export function checkInner(parsed: ParsedInner, ctx: ReceiveContext): Finding[] {
    const findings: Finding[] = [];
    const { meta } = parsed;
    if (!meta) {
        findings.push({
            level: "warning",
            code: "no-meta",
            text: parsed.metaError
                ? "The message's metadata is damaged. Sender and chat cannot be checked."
                : "The message has no dcpgp metadata. Sender and chat cannot be checked."
        });
        return findings;
    }

    if (meta.sender !== ctx.authorId)
        findings.push({ level: "error", code: "sender-mismatch", text: "The block was encrypted by another account and re-posted here. The displayed sender is not the author." });

    if (meta.channel !== ctx.channelId)
        findings.push({ level: "warning", code: "channel-mismatch", text: "The message comes from a different chat (copied or forwarded)." });

    if (ctx.myId !== meta.sender && !meta.recipients.includes(ctx.myId))
        findings.push({ level: "warning", code: "not-recipient", text: "You are not on the recipient list. The message was probably forwarded." });

    const skew = Math.abs(meta.time - ctx.discordTimeMs);
    if (skew > MAX_CLOCK_SKEW_MS)
        findings.push({ level: "warning", code: "time-mismatch", text: `The encrypted timestamp differs from Discord's by ${Math.round(skew / 60000)} minutes (old or replayed message?).` });

    return findings;
}

/** Discord counts UTF-16 code units in its client; we use the same, conservative measure. */
export function discordLength(content: string): number {
    return content.length;
}

/** Rough number of plaintext characters to remove so the message fits (armor ≈ 1.36 chars per byte). */
export function estimateOverflowChars(length: number, limit: number): number {
    if (length <= limit) return 0;
    return Math.ceil((length - limit) / 1.36) + PAD_BLOCK;
}
