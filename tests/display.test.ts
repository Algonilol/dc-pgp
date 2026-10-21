/*
 * DcPgp – message display decisions and the check of our own sent messages
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { canViewRawPgp, effectiveAutoDecrypt, hidesOriginal, type MarkInput, messageDisplay, ownEchoProblems, ownEchoVerdict, shouldMarkUnencrypted } from "../core/display";
import { parseContent } from "../core/format";
import { fingerprintOf, type PrivateKey } from "../core/pgp";
import { decryptForDisplay, type ReceiveKeys } from "../core/receive";
import { encryptForChannel } from "../core/send";
import { gpgKey, IDS } from "./helpers";

const T0 = 1_790_000_000_000;

describe("Showing messages", () => {
    it("decrypt automatically: the chat switch beats the global setting", () => {
        assert.equal(effectiveAutoDecrypt(true, undefined), true);
        assert.equal(effectiveAutoDecrypt(false, { encrypt: true }), false);
        assert.equal(effectiveAutoDecrypt(true, { encrypt: true, autoDecrypt: false }), false);
        assert.equal(effectiveAutoDecrypt(false, { encrypt: false, autoDecrypt: true }), true);
    });

    it("marks plaintext in encrypted chats only from the moment encryption was switched on", () => {
        const base: MarkInput = { enabled: true, phase: "unlocked", pref: { encrypt: true, since: T0 }, kind: "none", messageType: 0, sentAtMs: T0 + 1 };
        const mark = (over: Partial<MarkInput>) => shouldMarkUnencrypted({ ...base, ...over });
        assert.equal(mark({}), true);
        assert.equal(mark({ messageType: 19 }), true, "replies count too");
        assert.equal(mark({ sentAtMs: T0 - 1 }), false, "not older messages");
        assert.equal(mark({ kind: "message" }), false);
        assert.equal(mark({ kind: "keyreq" }), false, "key messages are readable on purpose");
        assert.equal(mark({ messageType: 7 }), false, "not system messages");
        assert.equal(mark({ pref: { encrypt: false } }), false);
        assert.equal(mark({ pref: undefined }), false);
        assert.equal(mark({ enabled: false }), false);
        assert.equal(mark({ phase: "locked" }), false, "while locked it is unknown since when the chat is encrypted");
    });

    it("placeholder depending on the state, plaintext only when unlocked", () => {
        const show = (over: Partial<Parameters<typeof messageDisplay>[0]>) =>
            messageDisplay({ phase: "unlocked", kind: "message", autoDecrypt: true, revealed: false, markUnencrypted: false, ...over });
        assert.deepEqual(show({}), { kind: "decrypt" });
        assert.deepEqual(show({ phase: "locked" }), { kind: "placeholder", reason: "locked" });
        assert.deepEqual(show({ phase: "nosetup" }), { kind: "placeholder", reason: "nosetup" });
        assert.deepEqual(show({ phase: "loading" }), { kind: "placeholder", reason: "loading" });
        assert.deepEqual(show({ autoDecrypt: false }), { kind: "placeholder", reason: "manual" });
        assert.deepEqual(show({ autoDecrypt: false, revealed: true }), { kind: "decrypt" });
        assert.deepEqual(show({ kind: "none" }), { kind: "none" });
        assert.deepEqual(show({ kind: "none", markUnencrypted: true }), { kind: "unencrypted" });
        assert.deepEqual(show({ kind: "keyresp" }), { kind: "key" });
        assert.deepEqual(show({ kind: "keyreq", phase: "locked" }), { kind: "key" }, "the card then shows \"Unlock\"");

        assert.equal(hidesOriginal(show({})), true);
        assert.equal(hidesOriginal(show({ kind: "keyreq" })), true, "the key block is replaced by the card");
        assert.equal(hidesOriginal(show({ phase: "locked" })), true, "ciphertext is hidden while locked too");
        assert.equal(hidesOriginal(show({ kind: "none", markUnencrypted: true })), false);
    });
});

describe("Raw ciphertext while locked", () => {
    const show = (over: Partial<Parameters<typeof messageDisplay>[0]>) =>
        messageDisplay({ phase: "locked", kind: "message", autoDecrypt: true, revealed: false, markUnencrypted: false, ...over });

    it("locked: placeholder by default, the raw block with the setting", () => {
        assert.deepEqual(show({ showRawWhenLocked: false }), { kind: "placeholder", reason: "locked" });
        assert.deepEqual(show({}), { kind: "placeholder", reason: "locked" }, "off unless set");
        assert.deepEqual(show({ showRawWhenLocked: true }), { kind: "raw" });
    });

    it("unlocked dcpgp/1 blocks are decrypted, other messages stay as before", () => {
        assert.deepEqual(show({ phase: "unlocked", showRawWhenLocked: true }), { kind: "decrypt" });
        assert.deepEqual(show({ kind: "none", showRawWhenLocked: true }), { kind: "none" });
        assert.deepEqual(show({ kind: "none", phase: "unlocked", markUnencrypted: true, showRawWhenLocked: true }), { kind: "unencrypted" });
        assert.deepEqual(show({ kind: "keyreq", showRawWhenLocked: true }), { kind: "key" }, "key messages keep their card");
        assert.deepEqual(show({ phase: "nosetup", showRawWhenLocked: true }), { kind: "placeholder", reason: "nosetup" }, "only when locked");
    });

    it("the raw block stays visible: Discord renders it, the plugin only adds buttons", () => {
        assert.equal(hidesOriginal({ kind: "raw" }), false);
        assert.equal(hidesOriginal(show({ showRawWhenLocked: true })), false);
    });
});

describe("View Raw PGP", () => {
    const show = (over: Partial<Parameters<typeof messageDisplay>[0]>) =>
        messageDisplay({ phase: "locked", kind: "message", autoDecrypt: true, revealed: false, markUnencrypted: false, ...over });

    it("is offered next to \"Unlock\" and in the raw view of 1:1 DMs", () => {
        assert.equal(canViewRawPgp(show({}), "dm"), true, "locked placeholder");
        assert.equal(canViewRawPgp(show({ showRawWhenLocked: true }), "dm"), true, "raw view");
    });

    it("not in group chats or servers", () => {
        for (const chat of ["group", "guild", "unsupported"] as const) {
            assert.equal(canViewRawPgp(show({}), chat), false, chat);
            assert.equal(canViewRawPgp(show({ showRawWhenLocked: true }), chat), false, chat);
        }
    });

    it("not when the message can be read or is no dcpgp/1 block", () => {
        assert.equal(canViewRawPgp(show({ phase: "unlocked" }), "dm"), false, "decrypted");
        assert.equal(canViewRawPgp(show({ phase: "unlocked", autoDecrypt: false }), "dm"), false, "\"Decrypt\" by hand is there");
        assert.equal(canViewRawPgp(show({ phase: "nosetup" }), "dm"), false);
        assert.equal(canViewRawPgp(show({ phase: "loading" }), "dm"), false);
        assert.equal(canViewRawPgp(show({ kind: "none" }), "dm"), false);
        assert.equal(canViewRawPgp(show({ kind: "keyreq" }), "dm"), false, "key messages have their card");
    });
});

describe("Checking our own sent messages", () => {
    it("verdict: verify, leak or skip", () => {
        const v = (over: Partial<Parameters<typeof ownEchoVerdict>[0]>) =>
            ownEchoVerdict({ sentHere: true, mustBeEncrypted: true, kind: "none", hasText: true, ...over });
        assert.equal(v({}), "leak", "plaintext in an encrypted chat from this PC");
        assert.equal(v({ kind: "message" }), "verify");
        assert.equal(v({ mustBeEncrypted: false }), "skip");
        assert.equal(v({ hasText: false }), "skip", "sticker/empty only: no text revealed");
        assert.equal(v({ kind: "keyreq" }), "skip");
        assert.equal(v({ sentHere: false }), "skip", "from another device: only marked");
        assert.equal(v({ sentHere: false, kind: "message" }), "skip");
    });

    async function sendAsAlice(alice: PrivateKey, bob: PrivateKey, signer = alice) {
        const content = await encryptForChannel({
            text: "Only for Bob",
            senderId: IDS.alice,
            channelId: IDS.dm,
            recipients: [{ userId: IDS.bob, key: bob.toPublic() }],
            ownPublic: alice.toPublic(),
            signer,
            time: T0,
            maxLength: 4000
        });
        const parsed = parseContent(content);
        assert.equal(parsed.kind, "message");
        return (parsed as { armored: string; }).armored;
    }

    const aliceSelf = (alice: PrivateKey): ReceiveKeys => ({
        decryptionKeys: [alice],
        ownPublic: [{ fpr: fingerprintOf(alice), key: alice.toPublic() }],
        author: null,
        authorName: "Alice",
        findContactByKeyId: () => null
    });

    const asEcho = (channelId: string) => ({ authorId: IDS.alice, channelId, myId: IDS.alice, discordTimeMs: T0 + 900 });

    it("an own message comes back correctly encrypted: no problems", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const armored = await sendAsAlice(alice, bob);
        const view = await decryptForDisplay(armored, asEcho(IDS.dm), aliceSelf(alice));
        assert.equal(view.text, "Only for Bob");
        assert.deepEqual(ownEchoProblems({ status: "ok", view }, IDS.dm), []);
    });

    it("a wrong chat or someone else's signature is reported", async () => {
        const [alice, bob] = await Promise.all([gpgKey("alice"), gpgKey("bob")]);
        const armored = await sendAsAlice(alice, bob);
        const elsewhere = await decryptForDisplay(armored, asEcho(IDS.other), aliceSelf(alice));
        assert.match(ownEchoProblems({ status: "ok", view: elsewhere }, IDS.other).join(" "), /different chat/);

        const forged = await sendAsAlice(alice, bob, bob);
        const view = await decryptForDisplay(forged, asEcho(IDS.dm), aliceSelf(alice));
        assert.match(ownEchoProblems({ status: "ok", view }, IDS.dm).join(" "), /someone else's key/);
    });

    it("unreadable or damaged is a problem, locked is not", () => {
        assert.match(ownEchoProblems({ status: "not-for-us" }, IDS.dm)[0], /cannot decrypt your own message/);
        assert.match(ownEchoProblems({ status: "error", error: "checksum" }, IDS.dm)[0], /damaged.*checksum/);
        assert.deepEqual(ownEchoProblems({ status: "locked" }, IDS.dm), []);
        assert.deepEqual(ownEchoProblems({ status: "pending" }, IDS.dm), []);
    });
});
