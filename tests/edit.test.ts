/*
 * DcPgp – editing encrypted messages: decisions for the edit box and for saving
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { editSave, editStart } from "../core/edit";

describe("Starting to edit", () => {
    it("an unencrypted message keeps Discord's own text", () => {
        assert.deepEqual(editStart({ encrypted: false, phase: "locked" }), { action: "keep" });
    });

    it("an encrypted message gets its plaintext into the edit box", () => {
        assert.deepEqual(editStart({ encrypted: true, phase: "unlocked", decryption: { status: "ok", text: "hello" } }), { action: "plaintext", text: "hello" });
        assert.deepEqual(editStart({ encrypted: true, phase: "unlocked", decryption: { status: "ok", text: "" } }), { action: "plaintext", text: "" });
    });

    it("no edit box with the PGP block in it", () => {
        const reason = (i: Parameters<typeof editStart>[0]) => {
            const r = editStart(i);
            return r.action === "refuse" ? r.message : r.action;
        };
        assert.match(reason({ encrypted: true, phase: "locked" }), /Unlock/);
        assert.match(reason({ encrypted: true, phase: "nosetup" }), /Unlock/);
        assert.equal(reason({ encrypted: true, phase: "unlocked" }), "wait", "not decrypted yet: the box opens once it is");
        assert.equal(reason({ encrypted: true, phase: "unlocked", decryption: { status: "pending" } }), "wait");
        assert.match(reason({ encrypted: true, phase: "unlocked", decryption: { status: "not-for-us" } }), /cannot be decrypted/);
        assert.match(reason({ encrypted: true, phase: "unlocked", decryption: { status: "error" } }), /cannot be decrypted/);
        assert.match(reason({ encrypted: true, phase: "unlocked", decryption: { status: "ok" } }), /cannot be decrypted/, "ok without text");
    });
});

describe("Saving an edit", () => {
    const base = { mustEncrypt: true, phase: "unlocked" as const, text: "new text", previousText: "old text" };

    it("ordinary edits outside encrypted chats are left alone", () => {
        assert.deepEqual(editSave({ ...base, mustEncrypt: false, phase: "locked" }), { action: "pass" });
        assert.deepEqual(editSave({ ...base, text: "  " }), { action: "pass" }, "empty: Discord deletes, the brake lets nothing out");
    });

    it("a changed text is encrypted, an unchanged one keeps the old block", () => {
        assert.deepEqual(editSave(base), { action: "encrypt" });
        assert.deepEqual(editSave({ ...base, previousText: undefined }), { action: "encrypt" }, "a plaintext message in an encrypted chat");
        assert.deepEqual(editSave({ ...base, text: "old text" }), { action: "unchanged" });
    });

    it("locked: refused", () => {
        assert.deepEqual(editSave({ ...base, phase: "locked" }), { action: "refuse", message: "DcPgp is locked." });
    });
});
