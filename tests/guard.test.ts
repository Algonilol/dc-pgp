/*
 * DcPgp – emergency brake and draft filter tests
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildKeyMessageContent, buildMessageContent } from "../core/format";
import { checkEdit, checkOutgoing, filterDraftState, type OutgoingCheck, stripSilent } from "../core/guard";

const ARMOR = "-----BEGIN PGP MESSAGE-----\n\nwV4DAAAAAAAAAAASAQdA\n-----END PGP MESSAGE-----";
const KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ\n-----END PGP PUBLIC KEY BLOCK-----";
const ENC = buildMessageContent(ARMOR);

const base: OutgoingCheck = { encrypted: true, content: "", allowedPlain: false, hasPoll: false, fromComposer: true, seenByHook: true };
const reason = (c: Partial<OutgoingCheck>) => {
    const v = checkOutgoing({ ...base, ...c });
    return v.ok ? "ok" : v.reason;
};

describe("Emergency brake when sending", () => {
    it("lets everything through in unencrypted chats", () => {
        assert.equal(reason({ encrypted: false, content: "hello" }), "ok");
        assert.equal(reason({ encrypted: false, content: "hello", fromComposer: true, seenByHook: false }), "ok");
    });

    it("blocks plaintext in encrypted chats", () => {
        assert.equal(reason({ content: "secret" }), "plaintext");
        assert.equal(reason({ content: "secret", fromComposer: false, seenByHook: false }), "plaintext");
    });

    it("reports a failed send hook separately", () => {
        assert.equal(reason({ content: "secret", seenByHook: false }), "hook-missing");
    });

    it("only lets dcpgp/1 content through, also with @silent", () => {
        assert.equal(reason({ content: ENC }), "ok");
        assert.equal(reason({ content: "@silent " + ENC }), "ok");
        assert.equal(reason({ content: buildKeyMessageContent("keyreq", KEY) }), "ok");
        assert.equal(reason({ content: "```\n" + ARMOR + "\n```" }), "plaintext", "a PGP block without the dcpgp marker does not count");
    });

    it("detects ciphertext that was changed afterwards", () => {
        assert.equal(reason({ content: ENC, expected: ENC }), "ok");
        assert.equal(reason({ content: "@silent " + ENC, expected: ENC }), "ok", "@silent from SilentMessageToggle is allowed");
        assert.equal(reason({ content: ENC + "\nhttps://example.org/sticker.png", expected: ENC }), "modified");
        assert.equal(reason({ content: "translated nonsense", expected: ENC }), "modified");
        assert.equal(reason({ encrypted: false, content: "x", expected: ENC }), "modified", "even if the chat is unencrypted by now");
    });

    it("empty messages (sticker/attachment only) pass, polls don't", () => {
        assert.equal(reason({ content: "" }), "ok");
        assert.equal(reason({ content: "   " }), "ok");
        assert.equal(reason({ content: "", hasPoll: true }), "poll");
    });

    it("an explicitly allowed plaintext message passes", () => {
        assert.equal(reason({ content: "secret", allowedPlain: true }), "ok");
    });

    it("only strips a leading @silent", () => {
        assert.equal(stripSilent("@silent hello"), "hello");
        assert.equal(stripSilent("hello @silent "), "hello @silent ");
    });
});

describe("Emergency brake when editing", () => {
    const edit = (c: Partial<Parameters<typeof checkEdit>[0]>) => {
        const v = checkEdit({ mustEncrypt: true, content: "", allowedPlain: false, ...c });
        return v.ok ? "ok" : v.reason;
    };

    it("blocks plaintext edits of encrypted messages", () => {
        assert.equal(edit({ content: "new plaintext", originalContent: ENC }), "plaintext");
        assert.equal(edit({ content: buildKeyMessageContent("keyresp", KEY) }), "plaintext", "edits must be message blocks");
    });

    it("lets encrypted and unchanged edits through", () => {
        assert.equal(edit({ content: ENC }), "ok");
        assert.equal(edit({ content: ENC, originalContent: ENC }), "ok");
        assert.equal(edit({ content: "old", originalContent: "old" }), "ok");
        assert.equal(edit({ mustEncrypt: false, content: "whatever" }), "ok");
    });

    it("detects changed edits", () => {
        assert.equal(edit({ content: ENC + "x", expected: ENC }), "modified");
    });
});

describe("Draft filter", () => {
    const state = {
        "111": {
            "900": { 0: { draft: "secret draft", timestamp: 1 } },
            "901": { 0: { draft: "harmless", timestamp: 2 } }
        },
        "222": { "900": { 0: { draft: "other account", timestamp: 3 } } }
    };

    it("leaves out drafts of encrypted chats when saving", () => {
        const out = filterDraftState(state, id => id === "900");
        assert.deepEqual(Object.keys(out["111"]), ["901"]);
        assert.deepEqual(out["222"], {});
        assert.equal(state["111"]["900"][0].draft, "secret draft", "the state in memory stays unchanged");
    });

    it("returns the original state when nothing is encrypted", () => {
        assert.equal(filterDraftState(state, () => false), state);
        assert.equal(filterDraftState(null, () => true), null);
    });
});
