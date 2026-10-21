/*
 * DcPgp – clipboard autoclear decisions
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { clipboardClearDelayMs, sameClipboardText } from "../core/clipboard";

describe("Clipboard autoclear", () => {
    const block = "-# 🔒 Encrypted message · dcpgp/1\n```\n-----BEGIN PGP MESSAGE-----\n\nwV4D\n-----END PGP MESSAGE-----\n```";

    it("recognises the copied text, also with Windows line endings", () => {
        assert.equal(sameClipboardText(block, block), true);
        assert.equal(sameClipboardText(block.replace(/\n/g, "\r\n"), block), true, "CRLF from the web clipboard API on Windows");
    });

    it("leaves anything else alone", () => {
        assert.equal(sameClipboardText(block + "x", block), false, "the whole text is compared");
        assert.equal(sameClipboardText(block.slice(0, 20), block), false, "a prefix is not enough");
        assert.equal(sameClipboardText("something the user copied later", block), false);
        assert.equal(sameClipboardText("", ""), false, "never clears for empty text");
    });

    it("waits the configured seconds, 0 means never", () => {
        assert.equal(clipboardClearDelayMs(60), 60_000);
        assert.equal(clipboardClearDelayMs(15), 15_000);
        assert.equal(clipboardClearDelayMs(0), null);
        assert.equal(clipboardClearDelayMs(-1), null);
        assert.equal(clipboardClearDelayMs(Number.NaN), null);
    });
});
