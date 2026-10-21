/*
 * DcPgp – what the lock menu and the user menu show, decided without any Discord code.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { ContactStatus } from "./contacts";
import type { ChannelPrefs, VaultData } from "./model";
import type { MissingReason } from "./send";

export type MenuPhase = "loading" | "nosetup" | "locked" | "unlocked";
export type ChatKind = "dm" | "group" | "guild" | "unsupported";

export function setChannelEncryption(data: VaultData, channelId: string, on: boolean, now = Date.now()) {
    const prev = data.channels[channelId];
    const next: ChannelPrefs = { ...prev, encrypt: on };
    if (on) next.since = prev?.encrypt && prev.since ? prev.since : now;
    else delete next.since;
    data.channels[channelId] = next;
}

/** Stores a per-chat exception only when it differs from the global setting. */
export function setChannelAutoDecrypt(data: VaultData, channelId: string, on: boolean, globalDefault: boolean) {
    const next: ChannelPrefs = { ...(data.channels[channelId] ?? { encrypt: false }) };
    if (on === globalDefault) delete next.autoDecrypt;
    else next.autoDecrypt = on;
    data.channels[channelId] = next;
}

export interface ChatMenuInput {
    phase: MenuPhase;
    kind: ChatKind;
    encrypted: boolean;
    oneShot: boolean;
    /** Effective value for this chat (per-chat switch or global setting). */
    autoDecrypt: boolean;
    hookHealthy: boolean;
    readers: { name: string; verified: boolean; }[];
    missing: { name: string; reason: MissingReason; }[];
    /**
     * Only for 1:1 DMs. `offer`: an unanswered key message from the partner is in the chat.
     * `hasContact`: a key of the partner is stored (the status hides that when they are blocked).
     * `keyExpiring`: the stored key expires within 30 days or has expired (`keyExpired`).
     */
    partner?: { name: string; status: ContactStatus; outgoingPending: boolean; offer?: boolean; hasContact?: boolean; keyExpiring?: boolean; keyExpired?: boolean; };
}

export type MenuEntry =
    | { type: "toggle"; id: "encrypt-all" | "encrypt-once" | "auto-decrypt"; label: string; checked: boolean; disabled: boolean; }
    | { type: "action"; id: "request-key" | "request-update" | "accept-key" | "verify" | "review-change" | "setup" | "unlock" | "lock" | "remove-contact"; label: string; danger?: boolean; }
    | { type: "info"; id: string; label: string; }
    | { type: "separator"; id: string; };

export type LockIcon = "off" | "on" | "unavailable" | "warning";

export interface ChatButtonModel {
    icon: LockIcon;
    tooltip: string;
    entries: MenuEntry[];
}

const info = (id: string, label: string): MenuEntry => ({ type: "info", id, label });

/**
 * The green dot on the lock button: an unlocked, encrypted chat with working send protection.
 * With a broken hook nothing promises "sent encrypted", so there is no dot.
 */
export function shouldShowEncryptedDot(phase: MenuPhase, encrypted: boolean, hookHealthy: boolean): boolean {
    return phase === "unlocked" && encrypted && hookHealthy;
}

/** Why encryption cannot be switched on right now, or null if it can. */
export function encryptionBlocker(i: ChatMenuInput): string | null {
    if (!i.hookHealthy) return "The send protection is broken (Discord update?). Encryption cannot be switched on.";
    if (i.kind === "dm") {
        const p = i.partner;
        if (!p) return "Chat partner unknown.";
        switch (p.status) {
            case "none":
                if (p.offer) return `${p.name} sent you a key – accept it first.`;
                return p.outgoingPending ? `Waiting for ${p.name}'s key.` : `Exchange keys with ${p.name} first.`;
            case "changed": return `${p.name} has a new key that is not confirmed yet.`;
            case "blocked": return `${p.name} is blocked.`;
            default: return p.keyExpired ? `${p.name}'s key has expired – request the updated key.` : null;
        }
    }
    return i.readers.length ? null : "Nobody in this chat has a stored key.";
}

export function chatButtonModel(i: ChatMenuInput): ChatButtonModel {
    if (i.phase === "loading")
        return { icon: "unavailable", tooltip: "Discord-PGP is loading …", entries: [info("loading", "Discord-PGP is loading …")] };
    if (i.phase === "nosetup")
        return {
            icon: "unavailable",
            tooltip: "Discord-PGP is not set up yet",
            entries: [info("nosetup", "Discord-PGP is not set up yet."), { type: "action", id: "setup", label: "Set up Discord-PGP …" }]
        };
    if (i.kind === "unsupported")
        return { icon: "unavailable", tooltip: "Discord-PGP: not available in this chat", entries: [info("unsupported", "Not available in this type of chat.")] };
    if (i.phase === "locked")
        return {
            icon: i.encrypted ? "on" : "unavailable",
            tooltip: i.encrypted ? "Encrypted chat – Discord-PGP is locked" : "Discord-PGP is locked",
            entries: [
                info("locked-state", i.encrypted ? "This chat is encrypted." : "This chat is not encrypted."),
                { type: "action", id: "unlock", label: "Unlock …" }
            ]
        };

    const blocker = encryptionBlocker(i);
    const entries: MenuEntry[] = [
        { type: "toggle", id: "encrypt-all", label: "Encrypt everything in this chat", checked: i.encrypted, disabled: !i.encrypted && blocker != null }
    ];
    if (!i.encrypted)
        entries.push({ type: "toggle", id: "encrypt-once", label: "Encrypt only the next message", checked: i.oneShot, disabled: blocker != null });
    if (blocker) entries.push(info("blocker", blocker));
    entries.push({ type: "toggle", id: "auto-decrypt", label: "Decrypt messages automatically", checked: i.autoDecrypt, disabled: false });

    const p = i.kind === "dm" ? i.partner : undefined;
    if (p) {
        entries.push({ type: "separator", id: "sep-partner" });
        switch (p.status) {
            case "none":
                entries.push(p.offer
                    ? { type: "action", id: "accept-key", label: `Accept ${p.name}'s key` }
                    : { type: "action", id: "request-key", label: p.outgoingPending ? `Send the key request to ${p.name} again` : `Request ${p.name}'s key` });
                break;
            case "unverified":
            case "trusted":
                if (p.keyExpiring) entries.push({ type: "action", id: "request-update", label: `Request ${p.name}'s updated key` });
                entries.push(p.status === "trusted"
                    ? { type: "action", id: "verify", label: "View safety number (verified)" }
                    : { type: "action", id: "verify", label: `Compare safety number with ${p.name}` });
                break;
            case "changed":
                entries.push({ type: "action", id: "review-change", label: `Review ${p.name}'s new key` });
                break;
            case "blocked":
                break;
        }
        if (p.hasContact || p.offer) entries.push({ type: "action", id: "remove-contact", label: "Remove contact …", danger: true });
    }

    if (i.readers.length)
        entries.push(info("readers", "Readable by: " + i.readers.map(r => r.name + (r.verified ? " ✓" : "")).join(", ")));
    if (i.kind !== "dm" && i.missing.length)
        entries.push(info("missing", `Without a key: ${i.missing.length}`));
    entries.push({ type: "separator", id: "sep-lock" }, { type: "action", id: "lock", label: "Lock now" });

    const active = i.encrypted || i.oneShot;
    return {
        icon: active ? (i.hookHealthy ? "on" : "warning") : "off",
        tooltip: i.encrypted ? "Encrypted – open the lock menu" : i.oneShot ? "The next message will be encrypted" : "Not encrypted – open the lock menu",
        entries
    };
}

export type UserMenuId = "request-key" | "request-update" | "verify" | "review-change" | "block" | "unblock" | "remove";

export interface UserMenuEntry {
    id: UserMenuId;
    label: string;
    danger?: boolean;
}

export function userMenuModel(status: ContactStatus, o: { outgoingPending: boolean; hasContact: boolean; keyExpiring?: boolean; }): UserMenuEntry[] {
    const entries: UserMenuEntry[] = [];
    switch (status) {
        case "none":
            entries.push({ id: "request-key", label: o.outgoingPending ? "Send key request again" : "Request key" });
            break;
        case "unverified":
        case "trusted":
            if (o.keyExpiring) entries.push({ id: "request-update", label: "Request updated key" });
            entries.push(status === "trusted"
                ? { id: "verify", label: "View safety number (verified)" }
                : { id: "verify", label: "Compare safety number" });
            break;
        case "changed":
            entries.push({ id: "review-change", label: "Review new key" });
            break;
        case "blocked":
            break;
    }
    entries.push(status === "blocked"
        ? { id: "unblock", label: "Unblock" }
        : { id: "block", label: "Block (no more key requests)", danger: true });
    if (o.hasContact) entries.push({ id: "remove", label: "Remove contact", danger: true });
    return entries;
}
