/*
 * DcPgp – how a message is shown (decrypted text, placeholder, "not encrypted" mark) and the
 * safety check of our own sent messages. Pure decisions, no Discord code.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { ParsedContent } from "./format";
import type { ChatKind, MenuPhase } from "./menus";
import type { ChannelPrefs } from "./model";
import type { DecryptedView } from "./receive";

export type ContentKind = ParsedContent["kind"];

/** Discord message types users write themselves: DEFAULT and REPLY. Joins, pins, calls etc. are never marked. */
const USER_MESSAGE_TYPES = new Set([0, 19]);

/** The per-chat switch from the lock menu wins over the global setting. */
export function effectiveAutoDecrypt(global: boolean, pref: ChannelPrefs | undefined): boolean {
    return pref?.autoDecrypt ?? global;
}

export interface MarkInput {
    enabled: boolean;
    phase: MenuPhase;
    /** Only known while unlocked; it says since when the chat is encrypted. */
    pref: ChannelPrefs | undefined;
    kind: ContentKind;
    messageType: number;
    sentAtMs: number;
}

/** Plaintext written into an encrypted chat after encryption was switched on. Key messages are public by design. */
export function shouldMarkUnencrypted(i: MarkInput): boolean {
    if (!i.enabled || i.phase !== "unlocked" || i.kind !== "none") return false;
    if (!i.pref?.encrypt || !USER_MESSAGE_TYPES.has(i.messageType)) return false;
    return i.sentAtMs >= (i.pref.since ?? 0);
}

export type PlaceholderReason = "loading" | "nosetup" | "locked" | "manual";

export type MessageDisplay =
    | { kind: "none"; }
    | { kind: "unencrypted"; }
    | { kind: "placeholder"; reason: PlaceholderReason; }
    | { kind: "decrypt"; }
    /** Key request/response: a card with the offer and buttons replaces the raw key block. */
    | { kind: "key"; }
    /** Locked, and the user wants to see the block: Discord shows it, we only add copy/unlock buttons. */
    | { kind: "raw"; };

export interface DisplayInput {
    phase: MenuPhase;
    kind: ContentKind;
    autoDecrypt: boolean;
    /** Decrypted by hand ("Decrypt") while auto-decrypt is off. */
    revealed: boolean;
    markUnencrypted: boolean;
    /** Setting "showRawCiphertextWhenLocked". */
    showRawWhenLocked?: boolean;
}

export function messageDisplay(i: DisplayInput): MessageDisplay {
    if (i.kind === "keyreq" || i.kind === "keyresp") return { kind: "key" };
    if (i.kind !== "message") return i.markUnencrypted ? { kind: "unencrypted" } : { kind: "none" };
    if (i.phase === "locked" && i.showRawWhenLocked) return { kind: "raw" };
    if (i.phase !== "unlocked") return { kind: "placeholder", reason: i.phase };
    if (!i.autoDecrypt && !i.revealed) return { kind: "placeholder", reason: "manual" };
    return { kind: "decrypt" };
}

/** The raw PGP block is replaced by our own rendering whenever we show something for it ("raw" keeps Discord's). */
export function hidesOriginal(d: MessageDisplay): boolean {
    return d.kind === "placeholder" || d.kind === "decrypt" || d.kind === "key";
}

/** "View Raw PGP": an encrypted message that can't be read right now (locked) or is shown raw – 1:1 DMs only. */
export function canViewRawPgp(d: MessageDisplay, chat: ChatKind): boolean {
    if (chat !== "dm") return false;
    return d.kind === "raw" || (d.kind === "placeholder" && d.reason === "locked");
}

export type EchoVerdict = "skip" | "verify" | "leak";

export interface EchoInput {
    /** The nonce matched an optimistic message of this client, i.e. it was sent from here. */
    sentHere: boolean;
    /** The chat was encrypted, or "next message only" was armed, when the message was sent. */
    mustBeEncrypted: boolean;
    kind: ContentKind;
    hasText: boolean;
}

/** What to do when Discord's server returns a message we sent. */
export function ownEchoVerdict(i: EchoInput): EchoVerdict {
    if (!i.sentHere) return "skip";
    if (i.kind === "message") return "verify";
    if (i.kind !== "none" || !i.hasText) return "skip";
    return i.mustBeEncrypted ? "leak" : "skip";
}

export type EchoResult =
    | { status: "ok"; view: DecryptedView; }
    | { status: "not-for-us"; }
    | { status: "error"; error?: string; }
    | { status: "locked"; }
    | { status: "pending"; };

/** Problems with an encrypted message we sent ourselves; empty when it arrived as intended. */
export function ownEchoProblems(r: EchoResult, channelId: string): string[] {
    switch (r.status) {
        case "locked":
        case "pending":
            return [];
        case "not-for-us":
            return ["You cannot decrypt your own message – it was not encrypted to your key."];
        case "error":
            return [`Your message arrived at Discord damaged${r.error ? ` (${r.error})` : ""}.`];
        case "ok": {
            const problems = r.view.findings.filter(f => f.level === "error").map(f => f.text);
            if (!r.view.meta) problems.push("Your message is missing the dcpgp metadata.");
            else if (r.view.meta.channel !== channelId) problems.push("Your message arrived in a different chat than the one it was encrypted for.");
            return problems;
        }
    }
}
