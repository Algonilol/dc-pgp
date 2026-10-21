/*
 * DcPgp – sending: encrypting for a chat, planning the recipients, mentions
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { buildInner, buildMessageContent, discordLength, estimateOverflowChars } from "./format";
import { isKeyExpired } from "./keyLifetime";
import type { Contact } from "./model";
import { encryptSigned, type PrivateKey, type PublicKey } from "./pgp";

export const MAX_READERS = 50;

export class TooLongError extends Error {
    constructor(public readonly length: number, public readonly limit: number) {
        super(`Encrypted, the message would be ${length} characters long, but only ${limit} are allowed. Shorten it by about ${estimateOverflowChars(length, limit)} characters or choose fewer recipients.`);
        this.name = "TooLongError";
    }
}

export interface EncryptRequest {
    text: string;
    senderId: string;
    channelId: string;
    recipients: { userId: string; key: PublicKey; }[];
    ownPublic: PublicKey;
    signer: PrivateKey;
    time: number;
    maxLength: number;
    /** Unencrypted line appended after the block, e.g. mentions that should still ping. */
    visibleSuffix?: string;
}

export async function encryptForChannel(req: EncryptRequest): Promise<string> {
    const inner = buildInner(req.text, {
        sender: req.senderId,
        channel: req.channelId,
        recipients: req.recipients.map(r => r.userId),
        time: req.time
    });
    const armored = await encryptSigned(inner, [...req.recipients.map(r => r.key), req.ownPublic], req.signer);
    inner.fill(0);
    const content = buildMessageContent(armored) + (req.visibleSuffix ? "\n" + req.visibleSuffix : "");
    const length = discordLength(content);
    if (length > req.maxLength) throw new TooLongError(length, req.maxLength);
    return content;
}

export type MissingReason = "no-key" | "key-changed" | "key-expired" | "blocked";

export interface RecipientCandidate {
    userId: string;
    name: string;
    contact: Contact | null;
}

export interface RecipientPlan {
    readers: { userId: string; name: string; contact: Contact; }[];
    missing: { userId: string; name: string; reason: MissingReason; }[];
}

export function planRecipients(candidates: RecipientCandidate[], blocked: Record<string, number>, selfId: string, now = Date.now()): RecipientPlan {
    const plan: RecipientPlan = { readers: [], missing: [] };
    const seen = new Set<string>();
    for (const c of candidates) {
        if (c.userId === selfId || seen.has(c.userId)) continue;
        seen.add(c.userId);
        if (blocked[c.userId]) plan.missing.push({ userId: c.userId, name: c.name, reason: "blocked" });
        else if (!c.contact) plan.missing.push({ userId: c.userId, name: c.name, reason: "no-key" });
        else if (c.contact.pendingKey) plan.missing.push({ userId: c.userId, name: c.name, reason: "key-changed" });
        else if (isKeyExpired(c.contact.keyExpires, now)) plan.missing.push({ userId: c.userId, name: c.name, reason: "key-expired" });
        else plan.readers.push({ userId: c.userId, name: c.name, contact: c.contact });
    }
    return plan;
}

export interface MentionInfo {
    users: string[];
    roles: string[];
    everyone: boolean;
}

export function findMentions(content: string): MentionInfo {
    const users = [...content.matchAll(/<@!?(\d{1,25})>/g)].map(m => m[1]);
    const roles = [...content.matchAll(/<@&(\d{1,25})>/g)].map(m => m[1]);
    const everyone = /(^|[^`\\])@(everyone|here)\b/.test(content);
    return { users: [...new Set(users)], roles: [...new Set(roles)], everyone };
}

export function hasMentions(m: MentionInfo): boolean {
    return m.users.length > 0 || m.roles.length > 0 || m.everyone;
}

export function mentionSuffix(m: MentionInfo): string {
    return [...m.users.map(u => `<@${u}>`), ...m.roles.map(r => `<@&${r}>`), ...(m.everyone ? ["@everyone"] : [])].join(" ");
}
