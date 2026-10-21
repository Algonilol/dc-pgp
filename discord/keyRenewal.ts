/*
 * DcPgp – keeps keys usable, once after every unlock: the own key gets a later expiry a year before it
 * runs out, and the expiry of every stored contact key is recorded. Decisions: core/keyLifetime.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { applyOwnKeyRenewal, isoDay, needsExtension } from "../core/keyLifetime";
import { armorKey, extendKey, keyExpiry, minimalPublicKey } from "../core/pgp";
import { toastInfo } from "../ui/dialogs";
import { logger, parsedKey, S, saveVault, type Session } from "./state";

async function renewOwnKey(session: Session): Promise<boolean> {
    const now = new Date();
    if (!needsExtension(await keyExpiry(session.privateKey), now.getTime())) return false;
    const extended = await extendKey(session.privateKey, now);
    const minimal = await minimalPublicKey(extended, now);
    if (S.session !== session) return false;
    session.privateKey = extended;
    session.ownPublic = minimal;
    session.ownPublicList[0] = { fpr: session.data.self.fpr, key: extended.toPublic() };
    applyOwnKeyRenewal(session.data, { publicKey: armorKey(minimal), privateKey: armorKey(extended) }, now.getTime());
    const until = await keyExpiry(extended);
    toastInfo(`Your DcPgp key was extended${until != null ? ` until ${isoDay(until)}` : ""}. Your contacts get the update the next time you write to them.`);
    return true;
}

/** Contacts stored before expiries were recorded get theirs once. */
async function recordContactExpiries(session: Session): Promise<boolean> {
    let changed = false;
    for (const contact of Object.values(session.data.contacts)) {
        if (contact.keyExpires !== undefined) continue;
        const key = await parsedKey(contact.publicKey).catch(() => null);
        if (!key) continue;
        const expires = await keyExpiry(key);
        if (S.session !== session) return false;
        contact.keyExpires = expires;
        changed = true;
    }
    return changed;
}

/** Never throws: if it fails, the key is simply not extended this time. */
export async function maintainKeys(session: Session): Promise<void> {
    try {
        const renewed = await renewOwnKey(session).catch(e => {
            logger.error("Extending the own key failed", e);
            return false;
        });
        const recorded = await recordContactExpiries(session);
        if ((renewed || recorded) && S.session === session) await saveVault();
    } catch (e) {
        logger.error("Key maintenance failed", e);
    }
}
