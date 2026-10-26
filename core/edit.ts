/*
 * DcPgp – editing encrypted messages: what goes into Discord's edit box, and what happens on saving.
 * Pure decisions; the Discord side is in discord/edits.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { MenuPhase } from "./menus";

export type EditStart =
    /** Not encrypted: Discord's own text goes into the edit box. */
    | { action: "keep"; }
    /** Our decrypted text replaces the PGP block in the edit box. */
    | { action: "plaintext"; text: string; }
    /** Not decrypted yet: open the edit box once it is. */
    | { action: "wait"; }
    /** No edit box: it would only show the PGP block. */
    | { action: "refuse"; message: string; };

export interface EditStartInput {
    /** The message's content is a dcpgp/1 message. */
    encrypted: boolean;
    phase: MenuPhase;
    decryption?: { status: "pending" | "ok" | "not-for-us" | "error" | "locked"; text?: string; };
}

export function editStart(i: EditStartInput): EditStart {
    if (!i.encrypted) return { action: "keep" };
    if (i.phase !== "unlocked") return { action: "refuse", message: "Unlock DcPgp to edit encrypted messages." };
    const d = i.decryption;
    if (d?.status === "ok" && d.text !== undefined) return { action: "plaintext", text: d.text };
    if (!d || d.status === "pending" || d.status === "locked") return { action: "wait" };
    return { action: "refuse", message: "This message cannot be decrypted, so it cannot be edited." };
}

export type EditSave =
    /** An ordinary edit outside encrypted chats: nothing to do. */
    | { action: "pass"; }
    /** The text is the same: the old block stays, so Discord saves nothing. */
    | { action: "unchanged"; }
    | { action: "encrypt"; }
    | { action: "refuse"; message: string; };

export interface EditSaveInput {
    /** The chat is encrypted, or the message being edited is. */
    mustEncrypt: boolean;
    phase: MenuPhase;
    /** The new text, as Discord parsed it from the edit box. */
    text: string;
    /** The decrypted text of the message being edited, if it is encrypted and decrypted. */
    previousText?: string;
}

export function editSave(i: EditSaveInput): EditSave {
    if (!i.mustEncrypt || !i.text.trim()) return { action: "pass" };
    if (i.phase !== "unlocked") return { action: "refuse", message: "DcPgp is locked." };
    if (i.previousText !== undefined && i.text === i.previousText) return { action: "unchanged" };
    return { action: "encrypt" };
}
