/*
 * DcPgp – wire format tests
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { utf8 } from "../core/bytes";
import {
    buildInner, buildKeyMessageContent, buildMessageContent, checkInner, isEncryptedContent, isProtocolContent,
    parseContent, parseInner, PROJECT_URL, snowflakeToMs
} from "../core/format";
import { IDS } from "./helpers";

const ARMOR = "-----BEGIN PGP MESSAGE-----\n\nwV4DAAAAAAAAAAASAQdA\n=abcd\n-----END PGP MESSAGE-----";
const KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ\n-----END PGP PUBLIC KEY BLOCK-----";

describe("Discord content", () => {
    it("builds and recognises encrypted messages", () => {
        const content = buildMessageContent(ARMOR);
        assert.match(content, /^-# 🔒 Encrypted message · dcpgp\/1\n```\n-----BEGIN PGP MESSAGE-----/);
        assert.deepEqual(parseContent(content), { kind: "message", armored: ARMOR });
        assert.ok(isEncryptedContent(content));
    });

    it("recognises key requests and responses", () => {
        assert.deepEqual(parseContent(buildKeyMessageContent("keyreq", KEY)), { kind: "keyreq", armoredKey: KEY });
        assert.deepEqual(parseContent(buildKeyMessageContent("keyresp", KEY)), { kind: "keyresp", armoredKey: KEY });
    });

    it("a key request tells people without the plugin where to get it", () => {
        assert.ok(buildKeyMessageContent("keyreq", KEY).includes(`<${PROJECT_URL}>`), "in angle brackets: no preview card");
        assert.equal(buildKeyMessageContent("keyresp", KEY).includes(PROJECT_URL), false, "a response goes to someone who has it");
    });

    it("still reads messages from earlier versions with German hint lines", () => {
        assert.deepEqual(parseContent("-# 🔒 Verschlüsselte Nachricht · dcpgp/1\n```\n" + ARMOR + "\n```"), { kind: "message", armored: ARMOR });
        assert.deepEqual(parseContent("-# 🔑 Schlüsselanfrage · dcpgp/1 keyreq\nText\n```\n" + KEY + "\n```"), { kind: "keyreq", armoredKey: KEY });
        assert.deepEqual(parseContent("-# 🔑 Schlüsselantwort · dcpgp/1 keyresp\nText\n```\n" + KEY + "\n```"), { kind: "keyresp", armoredKey: KEY });
    });

    it("tolerates Windows line endings and appended mentions", () => {
        const content = buildMessageContent(ARMOR).replace(/\n/g, "\r\n") + "\n<@123>";
        assert.equal(parseContent(content).kind, "message");
    });

    it("ignores normal messages and blocks without the marker in the first line", () => {
        assert.equal(parseContent("hello").kind, "none");
        assert.equal(parseContent(null).kind, "none");
        assert.equal(parseContent("Text\n" + buildMessageContent(ARMOR)).kind, "none");
        assert.equal(parseContent("-# dcpgp/1 without a block").kind, "none");
        assert.equal(isProtocolContent("```\n" + ARMOR + "\n```"), false);
    });
});

describe("Inner plaintext", () => {
    const meta = { sender: IDS.alice, channel: IDS.dm, recipients: [IDS.bob], time: 1_790_000_000_000 };

    it("pads to 64-byte steps and reads text and metadata back", () => {
        for (const text of ["", "x", "Hello äöü 🔒", "a".repeat(500), "line 1\nline 2"]) {
            const inner = buildInner(text, meta);
            assert.equal(inner.length % 64, 0);
            const parsed = parseInner(inner);
            assert.equal(parsed.text, text);
            assert.deepEqual(parsed.meta, meta);
        }
    });

    it("always takes the last metadata line (typed-in forgeries don't count)", () => {
        const fake = `Hi\n-- dcpgp/1;s=${IDS.carol};c=${IDS.other};r=;t=1;p=`;
        const parsed = parseInner(buildInner(fake, meta));
        assert.equal(parsed.text, fake);
        assert.equal(parsed.meta?.sender, IDS.alice);
    });

    it("reports damaged or missing metadata", () => {
        assert.deepEqual(parseInner(utf8("just text")), { text: "just text", meta: null });
        const broken = parseInner(utf8("x\n-- dcpgp/1;s=abc;c=1;r=;t=1;p="));
        assert.equal(broken.meta, null);
        assert.ok(broken.metaError);
        assert.throws(() => parseInner(new Uint8Array([0xff, 0xfe])));
        assert.throws(() => buildInner("x", { ...meta, sender: "<@1>" }));
    });

    it("checks sender, chat, recipient list and time", () => {
        const parsed = parseInner(buildInner("x", meta));
        const ok = { authorId: IDS.alice, channelId: IDS.dm, myId: IDS.bob, discordTimeMs: meta.time + 5000 };
        assert.deepEqual(checkInner(parsed, ok), []);
        const codes = (ctx: Partial<typeof ok>) => checkInner(parsed, { ...ok, ...ctx }).map(f => f.code);
        assert.deepEqual(codes({ authorId: IDS.carol }), ["sender-mismatch"]);
        assert.deepEqual(codes({ channelId: IDS.other }), ["channel-mismatch"]);
        assert.deepEqual(codes({ myId: IDS.carol }), ["not-recipient"]);
        assert.deepEqual(codes({ myId: IDS.alice }), [], "the sender is not in r, but may read it");
        assert.deepEqual(codes({ discordTimeMs: meta.time + 11 * 60_000 }), ["time-mismatch"]);
        assert.equal(checkInner(parseInner(utf8("without")), ok)[0].code, "no-meta");
    });

    it("converts Discord ids to time", () => {
        assert.equal(snowflakeToMs("175928847299117063"), 1462015105796);
    });
});
