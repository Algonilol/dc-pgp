/*
 * DcPgp – end-to-end send/receive tests (Alice -> Bob)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parseContent } from "../core/format";
import { fingerprintOf, keyHasKeyId, NotForUsError, type PrivateKey } from "../core/pgp";
import { decryptForDisplay, type ReceiveKeys } from "../core/receive";
import { encryptForChannel, TooLongError } from "../core/send";
import { gpgKey, IDS } from "./helpers";

const T0 = 1_790_000_000_000;

async function send(from: PrivateKey, to: PrivateKey[], opts: { text?: string; channel?: string; sender?: string; maxLength?: number; } = {}) {
    const content = await encryptForChannel({
        text: opts.text ?? "Meet at 6 pm? 🔒",
        senderId: opts.sender ?? IDS.alice,
        channelId: opts.channel ?? IDS.dm,
        recipients: to.map((k, i) => ({ userId: [IDS.bob, IDS.carol][i], key: k.toPublic() })),
        ownPublic: from.toPublic(),
        signer: from,
        time: T0,
        maxLength: opts.maxLength ?? 2000
    });
    const parsed = parseContent(content);
    assert.equal(parsed.kind, "message");
    return { content, armored: (parsed as any).armored as string };
}

function bobKeys(bob: PrivateKey, alice: PrivateKey | null, verified: boolean, others: PrivateKey[] = []): ReceiveKeys {
    return {
        decryptionKeys: [bob],
        ownPublic: [{ fpr: fingerprintOf(bob), key: bob.toPublic() }],
        author: alice ? { name: "Alice", verified, current: { fpr: fingerprintOf(alice), key: alice.toPublic() }, history: [] } : null,
        authorName: "Alice",
        findContactByKeyId: id => others.some(k => keyHasKeyId(k, id)) ? { userId: IDS.carol, name: "Carol" } : null
    };
}

const ctx = { authorId: IDS.alice, channelId: IDS.dm, myId: IDS.bob, discordTimeMs: T0 + 1500 };

describe("Sending and receiving", () => {
    it("verified contact: green lock without notes", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored, content } = await send(alice, [bob]);
        assert.ok(content.length < 1100, `a short 1:1 message fits easily (${content.length})`);
        const view = await decryptForDisplay(armored, ctx, bobKeys(bob, alice, true));
        assert.equal(view.text, "Meet at 6 pm? 🔒");
        assert.equal(view.trust, "verified");
        assert.deepEqual(view.findings, []);
    });

    it("unverified contact: grey lock with a note", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, ctx, bobKeys(bob, alice, false));
        assert.equal(view.trust, "unverified");
        assert.deepEqual(view.findings.map(f => f.code), ["not-verified"]);
    });

    it("unknown sender: readable, but not verifiable", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, ctx, bobKeys(bob, null, false));
        assert.equal(view.trust, "unverified");
        assert.ok(view.findings.some(f => f.code === "sig-unknown-sender"));
    });

    it("someone else's block re-posted under another name: check failed", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, { ...ctx, authorId: IDS.carol }, { ...bobKeys(bob, null, false), authorName: "Carol" });
        assert.equal(view.trust, "failed");
        assert.ok(view.findings.some(f => f.code === "sender-mismatch"));
    });

    it("copied into another chat: warning", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, { ...ctx, channelId: IDS.other }, bobKeys(bob, alice, true));
        assert.equal(view.trust, "verified");
        assert.ok(view.findings.some(f => f.code === "channel-mismatch"));
    });

    it("signed with another contact's key: check failed", async () => {
        const [alice, bob, rsa] = await Promise.all([gpgKey("alice"), gpgKey("bob"), gpgKey("rsa")]);
        const { armored } = await send(rsa, [bob], { sender: IDS.alice });
        const view = await decryptForDisplay(armored, ctx, bobKeys(bob, alice, true, [rsa]));
        assert.equal(view.trust, "failed");
        assert.ok(view.findings.some(f => f.code === "sig-other-contact"));
    });

    it("an own message is readable and verified for its sender", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const keys: ReceiveKeys = { ...bobKeys(alice, null, false), ownPublic: [{ fpr: fingerprintOf(alice), key: alice.toPublic() }] };
        const view = await decryptForDisplay(armored, { ...ctx, myId: IDS.alice }, keys);
        assert.equal(view.trust, "verified");
    });

    it("group: every recipient reads it, outsiders don't", async () => {
        const [alice, bob, rsa] = await Promise.all([gpgKey("alice"), gpgKey("bob"), gpgKey("rsa")]);
        const { armored } = await send(alice, [bob, rsa], { channel: IDS.other });
        for (const reader of [bob, rsa]) {
            const v = await decryptForDisplay(armored, { ...ctx, channelId: IDS.other, myId: reader === bob ? IDS.bob : IDS.carol }, bobKeys(reader, alice, true));
            assert.equal(v.trust, "verified");
        }
        const outsider = await import("openpgp").then(o => o.generateKey({ userIDs: [{ name: "x" }], format: "object" }));
        await assert.rejects(decryptForDisplay(armored, ctx, bobKeys(outsider.privateKey, alice, true)), NotForUsError);
    });

    it("too long: blocked instead of cut off", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        await assert.rejects(send(alice, [bob], { text: "x".repeat(1200) }), TooLongError);
        const fits = await send(alice, [bob], { text: "x".repeat(1200), maxLength: 4000 });
        assert.ok(fits.content.length <= 4000);
    });
});
