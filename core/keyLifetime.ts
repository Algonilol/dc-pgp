/*
 * DcPgp – key lifetimes: when the own key gets a later expiry, when a contact's key counts as expired,
 * and which contacts still need our extended key. Pure decisions; the crypto is in pgp.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Contact, OwnKey, VaultData } from "./model";

const DAY = 24 * 60 * 60 * 1000;

/** "2028-10-20" */
export const isoDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** The own key is extended once less than this is left: a year for contacts to receive the new copy. */
export const EXTEND_WHEN_LEFT_MS = 365 * DAY;
/** From here on the menus offer to request a contact's updated key. */
export const EXPIRY_WARNING_MS = 30 * DAY;

export function needsExtension(expires: number | null, now: number): boolean {
    return expires != null && expires - now < EXTEND_WHEN_LEFT_MS;
}

/** A key expiry that is not known yet (undefined) counts as valid; OpenPGP.js still refuses expired keys. */
export function isKeyExpired(keyExpires: number | null | undefined, now: number): boolean {
    return keyExpires != null && keyExpires <= now;
}

/** Expires within EXPIRY_WARNING_MS or has expired already. */
export function isKeyExpiringSoon(keyExpires: number | null | undefined, now: number): boolean {
    return keyExpires != null && keyExpires - now < EXPIRY_WARNING_MS;
}

/** The contact got our key before its last extension, so their copy runs out earlier than ours. */
export function needsOwnKeyUpdate(self: OwnKey, contact: Contact): boolean {
    return self.renewedAt != null && (contact.sentKeyAt ?? 0) < self.renewedAt;
}

/** Stores the extended own key. The private key is only replaced where it is stored ("Stored" mode). */
export function applyOwnKeyRenewal(data: VaultData, armored: { publicKey: string; privateKey: string; }, now = Date.now()) {
    data.self.publicKey = armored.publicKey;
    if (data.self.privateKey) data.self.privateKey = armored.privateKey;
    data.self.renewedAt = now;
}
