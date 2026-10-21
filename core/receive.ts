/*
 * DcPgp – receiving: decrypting a message and deciding how trustworthy it is
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { checkInner, type Finding, type InnerMeta, parseInner, type ReceiveContext } from "./format";
import { type DecryptResult, decryptVerified, type PrivateKey, type PublicKey } from "./pgp";

export type TrustLevel = "verified" | "unverified" | "failed";

export interface AuthorKeys {
    name: string;
    verified: boolean;
    current: { fpr: string; key: PublicKey; };
    history: { fpr: string; key: PublicKey; }[];
}

export interface ReceiveKeys {
    decryptionKeys: PrivateKey[];
    /** Own public keys (current first). Used when the author is the current user. */
    ownPublic: { fpr: string; key: PublicKey; }[];
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
                if (fpr && keys.ownPublic.some(k => k.fpr === fpr)) return { findings, ok: true };
                findings.push({ level: "error", code: "sig-foreign", text: "This message under your name is signed with someone else's key." });
                return { findings, ok: false };
            }
            if (!keys.author || !fpr) {
                findings.push({ level: "warning", code: "sig-unknown-sender", text: `No key of ${keys.authorName} is stored, so the signature cannot be checked.` });
                return { findings, ok: false };
            }
            if (fpr === keys.author.current.fpr) return { findings, ok: true };
            if (keys.author.history.some(h => h.fpr === fpr)) {
                findings.push({ level: "info", code: "sig-old-key", text: `Signed with an older key of ${keys.author.name}.` });
                return { findings, ok: true };
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
    const parsed = parseInner(result.data);
    const findings = checkInner(parsed, ctx);
    const sig = evaluateSignature(result.signature, ctx, keys);
    findings.push(...sig.findings);

    const hasError = findings.some(f => f.level === "error");
    const trust: TrustLevel = hasError
        ? "failed"
        : sig.ok && (isMe || keys.author?.verified) ? "verified" : "unverified";

    if (trust === "unverified" && sig.ok && !isMe)
        findings.push({ level: "info", code: "not-verified", text: `${keys.author?.name ?? keys.authorName} is not verified yet. Compare your safety numbers once.` });

    return {
        text: parsed.text,
        trust,
        findings,
        meta: parsed.meta,
        signerFpr: result.signature.signerFingerprint,
        signedAt: result.signature.created
    };
}
