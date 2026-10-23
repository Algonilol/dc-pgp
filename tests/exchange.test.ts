/*
 * DcPgp – key exchange decisions and contact actions
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    acceptPendingKey, blockUser, contactStatus, forgetContact, rejectPendingKey, removeContact, setVerified, unblockUser, validateIncomingKey
} from "../core/contacts";
import {
    applyAccept, applyBlock, applyChangeLater, applyDecline, applyStoreResponse, buildKeyMessage, canRequestAgain,
    decideIncoming, type IncomingContext, type KeyCardInput, type KeyCardModel, keyCardModel, KeyMessageTooLongError, markHandled,
    pendingOffer, precheckIncoming, recordOutgoing, REQUEST_COOLDOWN_MS
} from "../core/exchange";
import { parseContent } from "../core/format";
import { setChannelEncryption } from "../core/menus";
import { emptyVaultData } from "../core/model";
import { armorKey, fingerprintOf, minimalPublicKey } from "../core/pgp";
import { planRecipients } from "../core/send";
import { fixture, gpgKey, IDS } from "./helpers";

const MSG = "900000000000000001";
const MSG2 = "900000000000000002";
const T = 1_790_000_000_000;

async function setup() {
    const [alice, bob, rsa] = await Promise.all([gpgKey("alice"), gpgKey("bob"), gpgKey("rsa")]);
    const data = emptyVaultData({ publicKey: armorKey(await minimalPublicKey(alice)), fpr: fingerprintOf(alice), createdAt: 0 });
    const bobKey = await validateIncomingKey(armorKey(await minimalPublicKey(bob)));
    const rsaKey = await validateIncomingKey(armorKey(await minimalPublicKey(rsa)));
    const aliceKey = await validateIncomingKey(fixture("gpg-alice.pub.asc"));
    return { data, bobKey, rsaKey, aliceKey };
}

const ctx = (over: Partial<IncomingContext> = {}): IncomingContext =>
    ({ kind: "keyreq", messageId: MSG, authorId: IDS.bob, myId: IDS.alice, isDm: true, ...over });

describe("Incoming keys: decision", () => {
    it("ignores non-DMs, own, handled and blocked messages", async () => {
        const { data, bobKey } = await setup();
        assert.deepEqual(precheckIncoming(ctx({ isDm: false }), data), { action: "ignore", reason: "not-dm" });
        assert.deepEqual(precheckIncoming(ctx({ authorId: IDS.alice }), data), { action: "ignore", reason: "own-message" });
        applyDecline(data, MSG, T);
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data), { action: "ignore", reason: "handled" });
        blockUser(data, IDS.bob, T);
        assert.deepEqual(decideIncoming(ctx({ messageId: MSG2 }), bobKey.fpr, data), { action: "ignore", reason: "blocked" });
        assert.equal(precheckIncoming(ctx({ messageId: MSG2, authorId: IDS.carol }), data), null);
    });

    it("unknown request: ask; accepting stores it unverified", async () => {
        const { data, bobKey } = await setup();
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data), { action: "ask-new" });
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        const contact = applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        assert.equal(contact.verified, false);
        assert.equal(contactStatus(data, IDS.bob), "unverified");
        assert.deepEqual(data.handled[MSG], { at: T, result: "accepted" });
        assert.equal(data.outgoing[IDS.bob], undefined, "our own pending request is done with that");
    });

    it("an answer to our request is stored, an unsolicited answer is asked about", async () => {
        const { data, bobKey } = await setup();
        assert.deepEqual(decideIncoming(ctx({ kind: "keyresp" }), bobKey.fpr, data), { action: "ask-new" });
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        assert.deepEqual(decideIncoming(ctx({ kind: "keyresp" }), bobKey.fpr, data), { action: "store-response" });
        applyStoreResponse(data, IDS.bob, "Bob", bobKey, MSG, T);
        assert.equal(data.handled[MSG].result, "stored");
        assert.equal(contactStatus(data, IDS.bob), "unverified");
    });

    it("same key: a request offers to resend ours, a response is already known", async () => {
        const { data, bobKey } = await setup();
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        assert.deepEqual(decideIncoming(ctx({ messageId: MSG2 }), bobKey.fpr, data), { action: "ask-resend" });
        assert.deepEqual(decideIncoming(ctx({ messageId: MSG2, kind: "keyresp" }), bobKey.fpr, data), { action: "already-known" });
    });

    it("different key: ask; \"later\" pauses encryption", async () => {
        const { data, bobKey, rsaKey } = await setup();
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        setVerified(data, IDS.bob, true, T);
        assert.deepEqual(decideIncoming(ctx({ messageId: MSG2 }), rsaKey.fpr, data), { action: "ask-changed", previousFpr: bobKey.fpr });

        applyChangeLater(data, IDS.bob, rsaKey, MSG2, T);
        assert.equal(contactStatus(data, IDS.bob), "changed");
        assert.equal(data.contacts[IDS.bob].fpr, bobKey.fpr, "the old key stays for now");
        assert.equal(data.handled[MSG2].result, "declined");
        const plan = planRecipients([{ userId: IDS.bob, name: "Bob", contact: data.contacts[IDS.bob] }], data.blocked, IDS.alice);
        assert.deepEqual(plan.missing.map(m => m.reason), ["key-changed"]);
        assert.equal(setVerified(data, IDS.bob, true, T), false, "not verifiable while a change is pending");

        acceptPendingKey(data, IDS.bob, T);
        assert.equal(contactStatus(data, IDS.bob), "unverified", "the new key is no longer verified");
        assert.equal(data.contacts[IDS.bob].fpr, rsaKey.fpr);
        assert.equal(data.contacts[IDS.bob].history[0].fpr, bobKey.fpr);
        assert.equal(data.contacts[IDS.bob].history[0].replacedAt, T, "the key message is older than the stored key: dated by the acceptance");
    });

    it("a key change is dated by Discord's time of the announcement; a key used again starts afresh", async () => {
        const { data, bobKey, rsaKey } = await setup();
        const day = 86_400_000;
        const idAt = (ms: number) => String((BigInt(ms) - 1_420_070_400_000n) << 22n);
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);

        applyChangeLater(data, IDS.bob, rsaKey, idAt(T + day), T + day + 5000);
        acceptPendingKey(data, IDS.bob, T + 3 * day);
        assert.deepEqual(data.contacts[IDS.bob].history.map(h => [h.fpr, h.replacedAt]), [[bobKey.fpr, T + day]], "announced on day 1, accepted on day 3");

        applyAccept(data, IDS.bob, "Bob", bobKey, idAt(T + 4 * day), T + 4 * day);
        assert.deepEqual(data.contacts[IDS.bob].history.map(h => [h.fpr, h.replacedAt]), [[rsaKey.fpr, T + 4 * day]], "the current key is not in the history");

        applyAccept(data, IDS.bob, "Bob", rsaKey, idAt(T + 5 * day), T + 5 * day);
        assert.deepEqual(data.contacts[IDS.bob].history.map(h => [h.fpr, h.replacedAt]), [[bobKey.fpr, T + 5 * day]], "no stale entry from day 1");
    });

    it("rejects our own key and someone else's key under another name", async () => {
        const { data, bobKey, aliceKey } = await setup();
        assert.deepEqual(decideIncoming(ctx(), aliceKey.fpr, data), { action: "reject", reason: "own-key" });
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        assert.deepEqual(decideIncoming(ctx({ messageId: MSG2, authorId: IDS.carol }), bobKey.fpr, data),
            { action: "reject", reason: "belongs-to-other", otherName: "Bob" });
    });

    it("remembers handled messages with their result", async () => {
        const { data, bobKey } = await setup();
        markHandled(data, MSG, "accepted", T);
        assert.deepEqual(data.handled[MSG], { at: T, result: "accepted" });
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data), { action: "ignore", reason: "handled" });
    });

    it("blocking from a request", async () => {
        const { data } = await setup();
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        applyBlock(data, IDS.bob, MSG, T);
        assert.equal(contactStatus(data, IDS.bob), "blocked");
        assert.equal(data.handled[MSG].result, "blocked");
        assert.equal(data.outgoing[IDS.bob], undefined);
    });
});

describe("Crossing requests and pending offers", () => {
    it("a request while we are waiting ourselves: store and answer instead of a deadlock", async () => {
        const { data, bobKey } = await setup();
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data), { action: "store-crossing" });
        assert.deepEqual(decideIncoming(ctx({ kind: "keyresp" }), bobKey.fpr, data), { action: "store-response" });
        applyStoreResponse(data, IDS.bob, "Bob", bobKey, MSG, T);
        assert.equal(contactStatus(data, IDS.bob), "unverified");
        assert.equal(data.outgoing[IDS.bob], undefined, "nobody is waiting anymore");
        assert.deepEqual(decideIncoming(ctx({ kind: "keyresp", messageId: MSG2 }), bobKey.fpr, data), { action: "already-known" },
            "the other side's answer arrives quietly afterwards");
    });

    it("a click may revise an earlier decision, live messages may not; blocked stays blocked", async () => {
        const { data, bobKey } = await setup();
        applyDecline(data, MSG, T);
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data), { action: "ignore", reason: "handled" });
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data, { ignoreHandled: true }), { action: "ask-new" });
        blockUser(data, IDS.bob, T);
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data, { ignoreHandled: true }), { action: "ignore", reason: "blocked" });
    });

    it("pending offer: the partner's newest unanswered key message", async () => {
        const { data, bobKey } = await setup();
        const msgs = [
            { id: "900000000000000001", authorId: IDS.bob },
            { id: "900000000000000003", authorId: IDS.bob },
            { id: "900000000000000002", authorId: IDS.bob },
            { id: "900000000000000009", authorId: IDS.alice }
        ];
        assert.equal(pendingOffer(msgs, IDS.bob, data)?.id, "900000000000000003");
        assert.equal(pendingOffer([...msgs, { id: "1000000000000000000", authorId: IDS.bob }], IDS.bob, data)?.id, "1000000000000000000", "a longer id is newer");
        markHandled(data, "900000000000000003", "declined", T);
        assert.equal(pendingOffer(msgs, IDS.bob, data)?.id, "900000000000000002", "declined ones don't count");
        assert.equal(pendingOffer(msgs, IDS.carol, data), null);
        applyAccept(data, IDS.bob, "Bob", bobKey, "900000000000000002", T);
        assert.equal(pendingOffer(msgs, IDS.bob, data), null, "with a stored key there is nothing to accept");
    });
});

describe("Card under key messages", () => {
    const card = (over: Partial<KeyCardInput>) => keyCardModel({
        phase: "unlocked", kind: "keyreq", messageId: MSG, authorId: IDS.bob, authorName: "Bob", myId: IDS.alice, isDm: true, data: null, ...over
    });
    const ids = (m: KeyCardModel) => m.actions.map(a => a.id);

    it("locked, not set up, own message, group", async () => {
        assert.deepEqual(ids(card({ phase: "locked" })), ["unlock"]);
        assert.deepEqual(ids(card({ phase: "nosetup" })), ["setup"]);
        assert.deepEqual(ids(card({ phase: "loading" })), []);
        const { data } = await setup();
        assert.match(card({ authorId: IDS.alice, data }).text, /Your key request/);
        assert.deepEqual(ids(card({ isDm: false, data, check: { fpr: "X" } })), []);
    });

    it("new offer: accept or decline; after declining, accept anyway", async () => {
        const { data, bobKey } = await setup();
        assert.match(card({ data }).text, /checking/);
        const offer = card({ data, check: { fpr: bobKey.fpr } });
        assert.deepEqual(ids(offer), ["accept", "decline"]);
        assert.equal(offer.fpr, bobKey.fpr);
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        assert.deepEqual(ids(card({ data, check: { fpr: bobKey.fpr } })), ["accept", "decline"], "also for a crossing request");
        applyDecline(data, MSG, T);
        const declined = card({ data, check: { fpr: bobKey.fpr } });
        assert.deepEqual(ids(declined), ["accept"]);
        assert.match(declined.text, /declined/);
    });

    it("stored: offer verification, answer a repeated request", async () => {
        const { data, bobKey } = await setup();
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        const stored = card({ data, check: { fpr: bobKey.fpr } });
        assert.equal(stored.tone, "ok");
        assert.deepEqual(ids(stored), ["verify"], "our answer is already out");
        assert.deepEqual(ids(card({ data, messageId: MSG2, check: { fpr: bobKey.fpr } })), ["verify", "resend"]);
        setVerified(data, IDS.bob, true, T);
        assert.deepEqual(ids(card({ data, kind: "keyresp", messageId: MSG2, check: { fpr: bobKey.fpr } })), []);
    });

    it("different key: review; own key and invalid keys: warning", async () => {
        const { data, bobKey, rsaKey, aliceKey } = await setup();
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        const changed = card({ data, messageId: MSG2, check: { fpr: rsaKey.fpr } });
        assert.equal(changed.tone, "warning");
        assert.deepEqual(ids(changed), ["review"]);
        assert.equal(card({ data, messageId: MSG2, check: { fpr: aliceKey.fpr } }).tone, "danger");
        assert.match(card({ data, check: { error: "expired" } }).text, /Invalid key from Bob: expired/);
    });
});

describe("Outgoing requests", () => {
    it("at most one pending request per person and day", async () => {
        const { data } = await setup();
        assert.equal(canRequestAgain(data, IDS.bob, T), true);
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        assert.equal(canRequestAgain(data, IDS.bob, T + 60_000), false);
        assert.equal(canRequestAgain(data, IDS.bob, T + REQUEST_COOLDOWN_MS), true);
    });

    it("builds request and response and checks the length", async () => {
        const { data } = await setup();
        const req = buildKeyMessage("keyreq", data.self.publicKey, 2000);
        const parsed = parseContent(req);
        assert.equal(parsed.kind, "keyreq");
        assert.equal((parsed as any).armoredKey, data.self.publicKey.trim());
        assert.equal(parseContent(buildKeyMessage("keyresp", data.self.publicKey, 2000)).kind, "keyresp");

        const rsaFull = fixture("gpg-rsa.pub.asc");
        assert.throws(() => buildKeyMessage("keyreq", rsaFull, 2000), KeyMessageTooLongError);
        assert.equal(parseContent(buildKeyMessage("keyreq", rsaFull, 4000)).kind, "keyreq");
    });
});

describe("Contact management", () => {
    it("status: none, unverified, trusted, blocked", async () => {
        const { data, bobKey } = await setup();
        assert.equal(contactStatus(data, IDS.bob), "none");
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        assert.equal(setVerified(data, IDS.bob, true, T), true);
        assert.equal(contactStatus(data, IDS.bob), "trusted");
        assert.equal(data.contacts[IDS.bob].verifiedAt, T);
        setVerified(data, IDS.bob, false, T);
        assert.equal(contactStatus(data, IDS.bob), "unverified");
        assert.equal(data.contacts[IDS.bob].verifiedAt, undefined);
        blockUser(data, IDS.bob, T);
        assert.equal(contactStatus(data, IDS.bob), "blocked");
        unblockUser(data, IDS.bob);
        assert.equal(contactStatus(data, IDS.bob), "unverified");
        assert.equal(setVerified(data, IDS.carol, true, T), false);
    });

    it("removing and rejecting a key change", async () => {
        const { data, bobKey, rsaKey } = await setup();
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        applyChangeLater(data, IDS.bob, rsaKey, MSG2, T);
        assert.equal(rejectPendingKey(data, IDS.bob), true);
        assert.equal(contactStatus(data, IDS.bob), "unverified");
        assert.equal(data.contacts[IDS.bob].fpr, bobKey.fpr);
        assert.equal(rejectPendingKey(data, IDS.bob), false);
        assert.equal(removeContact(data, IDS.bob), true);
        assert.equal(contactStatus(data, IDS.bob), "none");
        assert.equal(removeContact(data, IDS.bob), false);
    });
});

describe("Removing a contact (lock menu / user menu)", () => {
    /** Bob as a contact with a pending key change, our open request, handled key messages and an encrypted DM. */
    async function connected() {
        const { data, bobKey, rsaKey } = await setup();
        applyAccept(data, IDS.bob, "Bob", bobKey, MSG, T);
        applyChangeLater(data, IDS.bob, rsaKey, MSG2, T);
        recordOutgoing(data, IDS.bob, IDS.dm, T);
        setChannelEncryption(data, IDS.dm, true, T);
        setChannelEncryption(data, IDS.other, true, T);
        return { data, bobKey };
    }

    it("clears the contact, its pending key and our open request", async () => {
        const { data } = await connected();
        assert.ok(data.contacts[IDS.bob].pendingKey);
        assert.equal(forgetContact(data, IDS.bob, IDS.dm), true);
        assert.equal(data.contacts[IDS.bob], undefined, "the pending key goes with the contact");
        assert.equal(data.outgoing[IDS.bob], undefined);
        assert.equal(contactStatus(data, IDS.bob), "none");
    });

    it("keeps handled key messages, so old ones are not offered again", async () => {
        const { data, bobKey } = await connected();
        const handled = structuredClone(data.handled);
        forgetContact(data, IDS.bob, IDS.dm);
        assert.deepEqual(data.handled, handled);
        assert.deepEqual(decideIncoming(ctx(), bobKey.fpr, data), { action: "ignore", reason: "handled" });
        assert.deepEqual(decideIncoming(ctx({ messageId: "900000000000000003" }), bobKey.fpr, data), { action: "ask-new" },
            "a new request is asked about again");
    });

    it("keeps a block", async () => {
        const { data } = await connected();
        blockUser(data, IDS.bob, T);
        forgetContact(data, IDS.bob, IDS.dm);
        assert.equal(data.blocked[IDS.bob], T);
        assert.equal(contactStatus(data, IDS.bob), "blocked");
    });

    it("the chat is no longer encrypted, other chats stay as they are", async () => {
        const { data } = await connected();
        forgetContact(data, IDS.bob, IDS.dm);
        assert.equal(data.channels[IDS.dm].encrypt, false);
        assert.equal(data.channels[IDS.dm].since, undefined);
        assert.equal(data.channels[IDS.other].encrypt, true);

        const { data: noDm } = await connected();
        assert.equal(forgetContact(noDm, IDS.bob, null), true);
        assert.equal(noDm.channels[IDS.dm].encrypt, true, "without a DM only the contact goes");
        assert.equal(forgetContact(noDm, IDS.bob, null), false, "nothing left to remove");
    });
});
