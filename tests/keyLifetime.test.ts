/*
 * DcPgp – key lifetimes: extending the own key, taking over a contact's extended key, expired keys
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import * as openpgp from "openpgp";

import { utf8 } from "../core/bytes";
import { applyKeyRefresh, refreshContactKey, validateIncomingKey } from "../core/contacts";
import { applyAccept, applyStoreResponse, buildKeyMessage, buildKeyUpdateMessage, markKeySent, recordOutgoing } from "../core/exchange";
import { parseContent } from "../core/format";
import { applyOwnKeyRenewal, isKeyExpired, isKeyExpiringSoon, needsExtension, needsOwnKeyUpdate } from "../core/keyLifetime";
import { type Contact, emptyVaultData } from "../core/model";
import {
    armorKey, decryptVerified, extendKey, fingerprintOf, inspectKey, KEY_LIFETIME_SECONDS, keyExpiry, minimalPublicKey, PGP_CONFIG,
    prepareOwnKey, type PrivateKey, readPublicKey
} from "../core/pgp";
import { decryptForDisplay } from "../core/receive";
import { planRecipients } from "../core/send";
import { gpgKey, IDS } from "./helpers";

const DAY = 24 * 60 * 60 * 1000;
const YEAR = 365 * DAY;
const NOW = Date.now();
const MSG = "900000000000000001";

/** A Curve25519 key like the mod makes, created `ago` ms before now. */
async function keyMadeAgo(ago: number, lifetimeSeconds = KEY_LIFETIME_SECONDS, name = "Alice"): Promise<PrivateKey> {
    const { privateKey } = await openpgp.generateKey({
        type: "ecc", curve: "curve25519Legacy", userIDs: [{ name }], keyExpirationTime: lifetimeSeconds,
        date: new Date(NOW - ago), format: "object", config: PGP_CONFIG
    });
    return privateKey;
}

/** A message to `recipient`, signed by `signer` at time `at`. */
async function signedAt(recipient: PrivateKey, signer: PrivateKey, at: number): Promise<string> {
    return openpgp.encrypt({
        message: await openpgp.createMessage({ binary: utf8("hello"), format: "binary" }),
        encryptionKeys: recipient.toPublic(), signingKeys: signer, date: new Date(at), format: "armored", config: PGP_CONFIG
    });
}

const contact = (over: Partial<Contact> = {}): Contact =>
    ({ userId: IDS.bob, name: "Bob", publicKey: "", fpr: "B", verified: true, addedAt: 0, history: [], ...over });

describe("Key lifetime: decisions", () => {
    it("extends the own key once less than a year is left", () => {
        assert.equal(needsExtension(null, NOW), false, "a key without expiry stays as it is");
        assert.equal(needsExtension(NOW + 2 * YEAR, NOW), false);
        assert.equal(needsExtension(NOW + 300 * DAY, NOW), true);
        assert.equal(needsExtension(NOW - DAY, NOW), true, "an expired key is extended too");
    });

    it("counts unknown expiries as valid and warns 30 days ahead", () => {
        assert.equal(isKeyExpired(undefined, NOW), false);
        assert.equal(isKeyExpired(null, NOW), false);
        assert.equal(isKeyExpired(NOW - 1, NOW), true);
        assert.equal(isKeyExpiringSoon(NOW + 10 * DAY, NOW), true);
        assert.equal(isKeyExpiringSoon(NOW + 60 * DAY, NOW), false);
        assert.equal(isKeyExpiringSoon(NOW - DAY, NOW), true, "expired counts as expiring");
    });

    it("knows which contacts still have a copy of our key from before its extension", () => {
        const data = emptyVaultData({ publicKey: "k", fpr: "F", createdAt: 0 });
        data.contacts[IDS.bob] = contact();
        assert.equal(needsOwnKeyUpdate(data.self, data.contacts[IDS.bob]), false, "never extended: nothing to send");

        applyOwnKeyRenewal(data, { publicKey: "k2", privateKey: "p2" }, 1000);
        assert.equal(data.self.publicKey, "k2");
        assert.equal(data.self.privateKey, undefined, "\"RAM only\": no private key is added to the vault");
        assert.equal(needsOwnKeyUpdate(data.self, data.contacts[IDS.bob]), true);

        markKeySent(data, IDS.bob, 2000);
        assert.equal(needsOwnKeyUpdate(data.self, data.contacts[IDS.bob]), false);

        const stored = emptyVaultData({ publicKey: "k", fpr: "F", createdAt: 0, privateKey: "p" });
        applyOwnKeyRenewal(stored, { publicKey: "k2", privateKey: "p2" }, 1000);
        assert.equal(stored.self.privateKey, "p2", "\"Stored\": the vault keeps the extended private key");
    });

    it("remembers that our own key request carried our key", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const data = emptyVaultData({ publicKey: armorKey(await minimalPublicKey(alice)), fpr: fingerprintOf(alice), createdAt: 0 });
        recordOutgoing(data, IDS.bob, IDS.dm, 5000);
        applyStoreResponse(data, IDS.bob, "Bob", await validateIncomingKey(armorKey(await minimalPublicKey(bob))), MSG, 9000);
        assert.equal(data.contacts[IDS.bob].sentKeyAt, 5000);
    });

    it("does not encrypt to a contact whose key has expired", () => {
        const plan = (keyExpires: number | null | undefined) =>
            planRecipients([{ userId: IDS.bob, name: "Bob", contact: contact({ keyExpires }) }], {}, IDS.alice, NOW);
        assert.deepEqual(plan(NOW - 1).missing.map(m => m.reason), ["key-expired"]);
        assert.equal(plan(NOW + DAY).readers.length, 1);
        assert.equal(plan(null).readers.length, 1, "never expires");
        assert.equal(plan(undefined).readers.length, 1, "not known yet: OpenPGP.js still refuses an expired key");
    });
});

describe("Key lifetime: extending keys", () => {
    it("gives the same key a later expiry; messages signed before stay verifiable", async () => {
        const [alice, bob] = await Promise.all([keyMadeAgo(1.5 * YEAR), keyMadeAgo(3 * YEAR, 0, "Bob")]);
        const before = await signedAt(bob, alice, NOW - YEAR);

        const extended = await extendKey(alice);
        assert.equal(fingerprintOf(extended), fingerprintOf(alice), "same key, same safety number");
        assert.ok(extended.isDecrypted());
        const expiry = await keyExpiry(extended);
        assert.ok(expiry != null && Math.abs(expiry - (NOW + KEY_LIFETIME_SECONDS * 1000)) < DAY, "valid for two more years");
        assert.deepEqual((await inspectKey(extended)).errors, []);

        const forContacts = await minimalPublicKey(extended);
        assert.equal((await decryptVerified(before, [bob], [forContacts])).signature.status, "valid");
        assert.equal((await decryptVerified(await signedAt(bob, extended, NOW), [bob], [forContacts])).signature.status, "valid");
    });

    it("brings back an expired key; a revoked key stays revoked", async () => {
        const expired = await keyMadeAgo(3 * YEAR);
        const report = await inspectKey(expired);
        assert.equal(report.expired, true);

        const prepared = await prepareOwnKey(expired);
        assert.deepEqual(prepared.report.errors, []);
        assert.match(prepared.report.warnings[0], /^The key had expired; DcPgp extended it until \d{4}-\d\d-\d\d\.$/);
        assert.equal(fingerprintOf(prepared.key), fingerprintOf(expired));

        const { privateKey: revoked } = await openpgp.revokeKey({ key: await keyMadeAgo(DAY), format: "object" });
        const kept = await prepareOwnKey(revoked);
        assert.equal(kept.key, revoked, "not extended");
        assert.ok(kept.report.errors.some(e => /revoked/.test(e)));
        await assert.rejects(extendKey(revoked));
    });

    it("sends contacts only the newest two self-signatures, so the key message stays small", async () => {
        let key = await keyMadeAgo(1.5 * YEAR);
        for (let i = 0; i < 3; i++) key = await extendKey(key, new Date(NOW + i * YEAR));
        const minimal = await minimalPublicKey(key, new Date(NOW + 2 * YEAR + DAY));
        assert.equal(key.users[0].selfCertifications.length, 4, "the own copy keeps all of them for old messages");
        assert.equal(minimal.users[0].selfCertifications.length, 2);
        assert.ok(minimal.subkeys.every(s => s.bindingSignatures.length <= 2));
        // The longest key message (a request) must still fit without Nitro, however often the key was extended.
        assert.doesNotThrow(() => buildKeyMessage("keyreq", armorKey(minimal), 2000));
        assert.doesNotThrow(() => buildKeyUpdateMessage(armorKey(minimal), 2000));
    });

    it("sends the update as a key response that older versions understand", async () => {
        const key = armorKey(await minimalPublicKey(await gpgKey("alice")));
        const content = buildKeyUpdateMessage(key, 2000);
        assert.match(content.split("\n")[0], /Key update/);
        const parsed = parseContent(content);
        assert.equal(parsed.kind, "keyresp");
        assert.equal((parsed as any).armoredKey, key.trim());
    });
});

describe("Key lifetime: a contact's extended key", () => {
    it("takes over the later expiry, keeps the verification, and nothing else", async () => {
        const alice = await keyMadeAgo(1.5 * YEAR);
        const data = emptyVaultData({ publicKey: "k", fpr: "F", createdAt: 0 });
        const first = await validateIncomingKey(armorKey(await minimalPublicKey(alice)));
        applyAccept(data, IDS.alice, "Alice", first, MSG);
        data.contacts[IDS.alice].verified = true;
        assert.equal(data.contacts[IDS.alice].keyExpires, first.report.expires!.getTime());

        const extended = await extendKey(alice);
        const update = await validateIncomingKey(armorKey(await minimalPublicKey(extended)));
        const refresh = await refreshContactKey(data.contacts[IDS.alice], update);
        assert.ok(refresh && refresh.keyExpires! > data.contacts[IDS.alice].keyExpires!);
        applyKeyRefresh(data, IDS.alice, refresh);
        assert.equal(data.contacts[IDS.alice].keyExpires, refresh.keyExpires);
        assert.equal(data.contacts[IDS.alice].verified, true, "same key material: the safety number still matches");

        assert.equal(await refreshContactKey(data.contacts[IDS.alice], update), null, "the same copy again adds nothing");
        assert.equal(await refreshContactKey(data.contacts[IDS.alice], first), null, "an older copy adds nothing");

        const other = await validateIncomingKey(armorKey(await minimalPublicKey(await keyMadeAgo(DAY, KEY_LIFETIME_SECONDS, "Mallory"))));
        assert.equal(await refreshContactKey(data.contacts[IDS.alice], other), null, "a different key is never merged");

        const { privateKey: twoIds } = await openpgp.reformatKey({
            privateKey: extended, userIDs: [{ name: "Alice" }, { name: "Mallory" }], keyExpirationTime: 3 * KEY_LIFETIME_SECONDS, format: "object", config: PGP_CONFIG
        });
        const sneaky = await refreshContactKey(data.contacts[IDS.alice], await validateIncomingKey(armorKey(twoIds.toPublic())));
        assert.ok(sneaky, "the newer self-signature is taken over");
        assert.deepEqual((await readPublicKey(sneaky.publicKey)).getUserIDs(), ["Alice"], "an added user id is not");
    });

    it("explains a signature made after the stored copy expired instead of calling it forged", async () => {
        const bob = await keyMadeAgo(4 * YEAR, 0, "Bob");
        // Expired two years ago, but extended before that (valid until half a year ago).
        const alice = await keyMadeAgo(3 * YEAR, 365 * 24 * 60 * 60);
        const extended = await extendKey(alice, new Date(NOW - 2.5 * YEAR));
        const message = await signedAt(bob, extended, NOW - YEAR);

        assert.equal((await decryptVerified(message, [bob], [alice.toPublic()])).signature.status, "expired-key");
        assert.equal((await decryptVerified(message, [bob], [extended.toPublic()])).signature.status, "valid");

        const view = await decryptForDisplay(message, { authorId: IDS.alice, channelId: IDS.dm, myId: IDS.bob, discordTimeMs: NOW - YEAR }, {
            decryptionKeys: [bob],
            ownPublic: [{ fpr: fingerprintOf(bob), key: bob.toPublic() }],
            author: { name: "Alice", verified: true, current: { fpr: fingerprintOf(alice), key: alice.toPublic() }, history: [] },
            authorName: "Alice",
            findContactByKeyId: () => null
        });
        assert.equal(view.trust, "failed", "nothing is verified until the update is in");
        assert.ok(view.findings.some(f => f.code === "sig-key-expired" && /Request their updated key/.test(f.text)));
    });
});
