/*
 * DcPgp – end-to-end send/receive tests (Alice -> Bob)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parseContent } from "../core/format";
import { fingerprintOf, keyHasKeyId, NotForUsError, type PrivateKey } from "../core/pgp";
import { decryptForDisplay, isEarlierId, markRepeated, noteCopy, type ReceiveKeys } from "../core/receive";
import { encryptForChannel, TooLongError } from "../core/send";
import { gpgKey, IDS } from "./helpers";

const T0 = 1_790_000_000_000;

async function send(from: PrivateKey, to: PrivateKey[], opts: { text?: string; channel?: string; sender?: string; maxLength?: number; time?: number; } = {}) {
    const content = await encryptForChannel({
        text: opts.text ?? "Meet at 6 pm? 🔒",
        senderId: opts.sender ?? IDS.alice,
        channelId: opts.channel ?? IDS.dm,
        recipients: to.map((k, i) => ({ userId: [IDS.bob, IDS.carol][i], key: k.toPublic() })),
        ownPublic: from.toPublic(),
        signer: from,
        time: opts.time ?? T0,
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

    it("copied into another chat: warning, and the lock is not green", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, { ...ctx, channelId: IDS.other }, bobKeys(bob, alice, true));
        assert.equal(view.trust, "unverified");
        assert.deepEqual(view.findings.map(f => f.code), ["channel-mismatch"], "no \"not verified\" note: Alice is verified");
    });

    it("old or replayed (Discord's time far from the signed one): not green", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, { ...ctx, discordTimeMs: T0 + 30 * 60_000 }, bobKeys(bob, alice, true));
        assert.equal(view.trust, "unverified");
        assert.deepEqual(view.findings.map(f => f.code), ["time-mismatch"]);
    });

    it("a replaced key: valid for messages from before the switch, an error after it", async () => {
        const [alice, bob, old] = await Promise.all([gpgKey("alice"), gpgKey("bob"), gpgKey("rsa")]);
        const switched = T0 + 60_000;
        const keys: ReceiveKeys = {
            ...bobKeys(bob, alice, true),
            author: {
                name: "Alice",
                verified: true,
                current: { fpr: fingerprintOf(alice), key: alice.toPublic() },
                history: [{ fpr: fingerprintOf(old), key: old.toPublic(), replacedAt: switched }]
            }
        };

        const before = await send(old, [bob]);
        const view = await decryptForDisplay(before.armored, ctx, keys);
        assert.equal(view.trust, "verified");
        assert.deepEqual(view.findings.map(f => f.code), ["sig-old-key"]);

        const late = switched + 60 * 60_000;
        const after = await send(old, [bob], { time: late });
        const forged = await decryptForDisplay(after.armored, { ...ctx, discordTimeMs: late + 1500 }, keys);
        assert.equal(forged.trust, "failed");
        assert.deepEqual(forged.findings.map(f => f.code), ["sig-replaced-key"]);
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

describe("Copies of an encrypted block", () => {
    it("the earliest message is the original, later ones are copies", () => {
        const first = new Map<string, string>();
        assert.deepEqual(noteCopy(first, "h1", "1000"), { repeated: false });
        assert.deepEqual(noteCopy(first, "h1", "1000"), { repeated: false }, "the same message again");
        assert.deepEqual(noteCopy(first, "h1", "2000"), { repeated: true });
        assert.deepEqual(noteCopy(first, "h1", "999"), { repeated: false, demoted: "1000" }, "an older message shows up later (scrolling up)");
        assert.deepEqual(noteCopy(first, "h1", "1000"), { repeated: true });
        assert.deepEqual(noteCopy(first, "h2", "2000"), { repeated: false }, "another block");
    });

    it("compares snowflakes as numbers and forgets the oldest blocks first", () => {
        assert.equal(isEarlierId("999", "1000"), true);
        assert.equal(isEarlierId("1000", "999"), false);
        assert.equal(isEarlierId("1000", "1000"), false);
        const first = new Map<string, string>();
        for (let i = 0; i < 4; i++) noteCopy(first, "h" + i, "100" + i, 3);
        assert.deepEqual([...first.keys()], ["h1", "h2", "h3"]);
    });

    it("a copy gets a warning and never a green lock", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const { armored } = await send(alice, [bob]);
        const view = await decryptForDisplay(armored, ctx, bobKeys(bob, alice, true));
        const copy = markRepeated(view);
        assert.equal(copy.trust, "unverified");
        assert.ok(copy.findings.some(f => f.code === "repeated" && f.level === "warning"));
        assert.equal(markRepeated(copy), copy, "marked once");
        assert.equal(view.trust, "verified", "the original view stays as it was");
    });
});
