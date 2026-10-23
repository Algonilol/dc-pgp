/*
 * DcPgp – receiving: decrypting a message and deciding how trustworthy it is
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { sha256Hex } from "./bytes";
import { checkInner, type Finding, type InnerMeta, MAX_CLOCK_SKEW_MS, parseInner, type ReceiveContext } from "./format";
import { type DecryptResult, decryptVerified, type PrivateKey, type PublicKey } from "./pgp";

export type TrustLevel = "verified" | "unverified" | "failed";

export interface AuthorKeys {
    name: string;
    verified: boolean;
    current: { fpr: string; key: PublicKey; };
    /** Replaced keys; `replacedAt`: when the next key was announced (Discord's time, ms; 0 = not recorded). */
    history: { fpr: string; key: PublicKey; replacedAt: number; }[];
}

export interface ReceiveKeys {
    decryptionKeys: PrivateKey[];
    /** Own public keys (current first; `retiredAt` only for replaced ones, 0 = not recorded). Used when the author is the current user. */
    ownPublic: { fpr: string; key: PublicKey; retiredAt?: number; }[];
    /** Stored key(s) of the author, or null if the author is not a contact. */
    author: AuthorKeys | null;
    authorName: string;
    /** Finds which contact (if any) owns a key id, to explain signature mismatches. */
    findContactByKeyId(keyIdHex: string): { userId: string; name: string; } | null;
}

export interface DecryptedView {
    text: string;
    trust: TrustLevel;
    findings: Finding[];
    meta: InnerMeta | null;
    signerFpr?: string;
    signedAt?: Date;
    /** SHA-256 of the decrypted content: the same for every copy of a message, however its block is formatted. */
    contentId: string;
}

/** A replaced key may have signed earlier messages, but none that Discord got after the switch (`at`; 0 = not recorded). */
function replacedKeyProblem(at: number, ctx: ReceiveContext, whose: string): Finding | null {
    if (!(at > 0))
        return { level: "warning", code: "sig-old-key-unknown", text: `Signed with ${whose} old key, but when it was replaced is not recorded, so it is unclear whether the message is from before the switch.` };
    if (ctx.discordTimeMs > at + MAX_CLOCK_SKEW_MS)
        return { level: "error", code: "sig-replaced-key", text: `Signed with ${whose} old key, although it was sent after the key was replaced. It may be forged by someone who has the old key.` };
    return null;
}

function evaluateSignature(sig: DecryptResult["signature"], ctx: ReceiveContext, keys: ReceiveKeys): { findings: Finding[]; ok: boolean; } {
    const isMe = ctx.authorId === ctx.myId;
    const findings: Finding[] = [];

    switch (sig.status) {
        case "missing":
            findings.push({ level: "error", code: "sig-missing", text: "The message is not signed. The sender cannot be proven." });
            return { findings, ok: false };
        case "invalid":
            findings.push({ level: "error", code: "sig-invalid", text: "The signature is invalid. The content may have been altered." });
            return { findings, ok: false };
        case "expired-key":
            // Not proof of a forgery, but nothing is verified either: it stays an error until the update is in.
            findings.push({
                level: "error",
                code: "sig-key-expired",
                text: isMe
                    ? "Your key had expired when this message was signed, so the signature cannot be checked."
                    : `The stored key of ${keys.author?.name ?? keys.authorName} has expired, so the signature cannot be checked. Request their updated key in the lock menu.`
            });
            return { findings, ok: false };
        case "unknown-key": {
            if (isMe) {
                findings.push({ level: "error", code: "sig-foreign", text: "This message under your name is signed with someone else's key." });
                return { findings, ok: false };
            }
            if (!keys.author) {
                findings.push({ level: "warning", code: "sig-unknown-sender", text: `No key of ${keys.authorName} is stored, so the signature cannot be checked. Request their key.` });
                return { findings, ok: false };
            }
            const other = sig.keyId ? keys.findContactByKeyId(sig.keyId) : null;
            findings.push(other
                ? { level: "error", code: "sig-other-contact", text: `Signed with the key of ${other.name}, not with the key of ${keys.author.name}.` }
                : { level: "error", code: "sig-wrong-key", text: `Signed with an unknown key instead of the stored key of ${keys.author.name}. Either ${keys.author.name} has a new key, or the message is forged.` });
            return { findings, ok: false };
        }
        case "valid": {
            const fpr = sig.signerFingerprint;
            if (isMe) {
                const own = fpr ? keys.ownPublic.find(k => k.fpr === fpr) : undefined;
                if (!own) {
                    findings.push({ level: "error", code: "sig-foreign", text: "This message under your name is signed with someone else's key." });
                    return { findings, ok: false };
                }
                const problem = own.retiredAt === undefined ? null : replacedKeyProblem(own.retiredAt, ctx, "your");
                if (problem) findings.push(problem);
                return { findings, ok: !problem };
            }
            if (!keys.author || !fpr) {
                findings.push({ level: "warning", code: "sig-unknown-sender", text: `No key of ${keys.authorName} is stored, so the signature cannot be checked.` });
                return { findings, ok: false };
            }
            if (fpr === keys.author.current.fpr) return { findings, ok: true };
            const old = keys.author.history.find(h => h.fpr === fpr);
            if (old) {
                const problem = replacedKeyProblem(old.replacedAt, ctx, `${keys.author.name}'s`);
                findings.push(problem ?? { level: "info", code: "sig-old-key", text: `Signed with an older key of ${keys.author.name}.` });
                return { findings, ok: !problem };
            }
            findings.push({ level: "error", code: "sig-wrong-key", text: `Signed with a key that does not belong to ${keys.author.name}.` });
            return { findings, ok: false };
        }
    }
}

/**
 * Decrypts a dcpgp message and decides how trustworthy it is.
 * Throws NotForUsError when none of our keys can open it.
 */
export async function decryptForDisplay(armored: string, ctx: ReceiveContext, keys: ReceiveKeys): Promise<DecryptedView> {
    const isMe = ctx.authorId === ctx.myId;
    const verificationKeys = isMe
        ? keys.ownPublic.map(k => k.key)
        : keys.author ? [keys.author.current.key, ...keys.author.history.map(h => h.key)] : [];

    const result = await decryptVerified(armored, keys.decryptionKeys, verificationKeys);
    const contentId = await sha256Hex(result.data);
    const parsed = parseInner(result.data);
    const findings = checkInner(parsed, ctx);
    const sig = evaluateSignature(result.signature, ctx, keys);
    findings.push(...sig.findings);

    const hasError = findings.some(f => f.level === "error");
    // Green means: the right person, in this chat, now. A forwarded, misdirected or old copy is not green.
    const hasWarning = findings.some(f => f.level === "warning");
    const trust: TrustLevel = hasError
        ? "failed"
        : sig.ok && !hasWarning && (isMe || keys.author?.verified) ? "verified" : "unverified";

    if (trust === "unverified" && sig.ok && !isMe && !keys.author?.verified)
        findings.push({ level: "info", code: "not-verified", text: `${keys.author?.name ?? keys.authorName} is not verified yet. Compare your safety numbers once.` });

    return {
        text: parsed.text,
        trust,
        findings,
        meta: parsed.meta,
        signerFpr: result.signature.signerFingerprint,
        signedAt: result.signature.created,
        contentId
    };
}

/** A message as the copy check sees it: its id, and Discord's time for it with the latest edit counted. */
export interface CopyRef {
    id: string;
    at: number;
}

/** Earlier by Discord's time – so an old message edited to carry a newer block counts as later – then by id. */
export function isEarlierCopy(a: CopyRef, b: CopyRef): boolean {
    if (a.at !== b.at) return a.at < b.at;
    // Snowflake ids grow with time; compared as numbers without BigInt.
    return a.id.length !== b.id.length ? a.id.length < b.id.length : a.id < b.id;
}

export interface CopyCheck {
    repeated: boolean;
    /** A message noted before that turned out to be the later copy. */
    demoted?: string;
}

/**
 * Every message has its own content (send time, random padding), so the same content in a second message
 * means it was replayed or re-posted – even with its block re-formatted. `first` maps a content id to the
 * earliest message seen with it; that one is the original.
 */
export function noteCopy(first: Map<string, CopyRef>, contentId: string, message: CopyRef, max = 5000): CopyCheck {
    const known = first.get(contentId);
    if (known?.id === message.id) return { repeated: false };
    if (known !== undefined && isEarlierCopy(known, message)) return { repeated: true };
    first.delete(contentId);
    first.set(contentId, message);
    while (first.size > max) first.delete(first.keys().next().value!);
    return known === undefined ? { repeated: false } : { repeated: false, demoted: known.id };
}

/** Whether a message is a later copy, going by what noteCopy has recorded. */
export function isCopy(first: Map<string, CopyRef>, contentId: string, messageId: string): boolean {
    const known = first.get(contentId);
    return known !== undefined && known.id !== messageId;
}

/** The view of a copy: a warning, and never a green lock. */
export function markRepeated(view: DecryptedView): DecryptedView {
    if (view.findings.some(f => f.code === "repeated")) return view;
    return {
        ...view,
        trust: view.trust === "verified" ? "unverified" : view.trust,
        findings: [...view.findings, { level: "warning", code: "repeated", text: "An earlier message already contained exactly this encrypted message – this one is a copy (replayed or re-posted)." }]
    };
}
