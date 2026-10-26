/*
 * DcPgp – encrypted attachments: naming, ids, decisions, the signed list and the file encryption itself
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
    type AttachInput, attachmentId, attachStart, checkUploadsForSend, compareWithList, encryptedFileName, isEncryptedFileName,
    MAX_ATTACHMENT_BYTES, previewOf, readersKey, safeFileName
} from "../core/attachments";
import { utf8 } from "../core/bytes";
import { buildInner, parseInner } from "../core/format";
import { checkOutgoing } from "../core/guard";
import { decryptFileVerified, encryptFileSigned, fingerprintOf, NotForUsError } from "../core/pgp";
import { gpgKey, IDS } from "./helpers";

describe("Encrypted attachments: names and ids", () => {
    it("Discord only sees a neutral name", () => {
        assert.equal(encryptedFileName(0), "dcpgp-1.pgp");
        assert.equal(isEncryptedFileName("dcpgp-10.pgp"), true);
        assert.equal(isEncryptedFileName("holiday.jpg"), false);
        assert.equal(isEncryptedFileName("dcpgp-1.pgp.exe"), false);
        assert.equal(isEncryptedFileName(undefined), false);
    });

    it("the id is 128 bits of SHA-256, url-safe, the same for the same bytes", async () => {
        const a = await attachmentId(utf8("encrypted bytes"));
        assert.match(a, /^[A-Za-z0-9_-]{22}$/);
        assert.equal(await attachmentId(utf8("encrypted bytes")), a);
        assert.notEqual(await attachmentId(utf8("encrypted bytes!")), a);
    });

    it("names from inside the encryption are made safe", () => {
        assert.equal(safeFileName("photo.jpg"), "photo.jpg");
        assert.equal(safeFileName("C:\\Users\\x\\secret.pdf"), "secret.pdf");
        assert.equal(safeFileName("../../evil.txt"), "evil.txt");
        assert.equal(safeFileName("a\u0000b.txt"), "ab.txt");
        assert.equal(safeFileName("invoice\u202efdp.exe"), "invoicefdp.exe", "no direction marks that fake the extension");
        assert.equal(safeFileName(".hidden"), "hidden");
        assert.equal(safeFileName(""), "attachment");
        assert.equal(safeFileName(undefined), "attachment");
        assert.equal(safeFileName("x".repeat(500)).length, 120);
    });

    it("only real media formats are shown inline, chosen by the name", () => {
        assert.deepEqual(previewOf("a.PNG"), { kind: "image", mime: "image/png" });
        assert.deepEqual(previewOf("clip.mp4"), { kind: "video", mime: "video/mp4" });
        assert.deepEqual(previewOf("voice.ogg"), { kind: "audio", mime: "audio/ogg" });
        for (const name of ["drawing.svg", "page.html", "notes.txt", "noextension"])
            assert.equal(previewOf(name).kind, "file", name);
    });
});

describe("Encrypted attachments: decisions", () => {
    const base: AttachInput = { encrypted: true, phase: "unlocked", dm: true, channelMessage: true, files: [{ size: 1000 }], alreadyAttached: 0 };
    const action = (o: Partial<AttachInput>) => {
        const r = attachStart({ ...base, ...o });
        return r.action === "refuse" ? r.message : r.action;
    };

    it("only encrypted chats are touched", () => {
        assert.equal(action({ encrypted: false, phase: "locked", dm: false }), "keep");
        assert.equal(action({}), "encrypt");
    });

    it("never lets Discord upload a file unencrypted in an encrypted chat", () => {
        assert.match(action({ phase: "locked" }), /locked.*NOT attached/);
        assert.match(action({ dm: false }), /1:1 DMs/);
        assert.match(action({ channelMessage: false }), /1:1 DMs/);
        assert.match(action({ alreadyAttached: 9, files: [{ size: 1 }, { size: 1 }] }), /At most 10/);
        assert.match(action({ files: [{ size: MAX_ATTACHMENT_BYTES + 1 }] }), /up to 100\.0 MB/);
        assert.match(action({ files: [{ size: 0 }] }), /empty/);
    });

    it("on sending: only DcPgp's files, for exactly the current readers", () => {
        const readers = readersKey([{ userId: "2", fpr: "B" }, { userId: "1", fpr: "A" }]);
        assert.equal(readers, readersKey([{ userId: "1", fpr: "A" }, { userId: "2", fpr: "B" }]), "order does not matter");
        assert.deepEqual(checkUploadsForSend([{ encrypted: { id: "x", readers } }, { encrypted: { id: "y", readers } }], readers), { ids: ["x", "y"] });
        assert.match((checkUploadsForSend([{ encrypted: { id: "x", readers } }, {}], readers) as any).error, /^Remove the file and attach it again – it was added before this chat was encrypted/);
        assert.match((checkUploadsForSend([{ encrypted: { id: "x", readers: "old" } }], readers) as any).error, /^Remove the files and attach them again – the keys in this chat changed/);
        assert.deepEqual(checkUploadsForSend([], readers), { ids: [] });
    });

    it("the files that arrived are compared with the signed list", () => {
        assert.deepEqual(compareWithList(["a", "b"], ["a", "b"]).problems, []);
        assert.deepEqual(compareWithList(["a"], ["a", "x"]).problems, ["not-listed"]);
        assert.deepEqual(compareWithList(["a", "b"], ["a"]).problems, ["missing"]);
        assert.deepEqual(compareWithList(undefined, ["a"]).problems, ["not-listed"]);
    });

    it("the emergency brake stops a file DcPgp did not encrypt", () => {
        const check = { encrypted: true, content: "", allowedPlain: false, hasPoll: false, fromComposer: false, seenByHook: false };
        assert.deepEqual(checkOutgoing({ ...check, foreignUploads: 1 }), { ok: false, reason: "attachment", message: "This chat is encrypted, but an attachment is not. It was NOT sent." });
        assert.deepEqual(checkOutgoing({ ...check, foreignUploads: 0 }), { ok: true });
        assert.deepEqual(checkOutgoing({ ...check, encrypted: false, foreignUploads: 2 }), { ok: true }, "normal chats are not touched");
    });
});

describe("Encrypted attachments: the signed list in the message", () => {
    const meta = { sender: IDS.alice, channel: IDS.dm, recipients: [IDS.bob], time: 1_790_000_000_000 };
    const id = "AAAAAAAAAAAAAAAAAAAAAA";

    it("round-trips and old messages have none", () => {
        assert.deepEqual(parseInner(buildInner("hi", { ...meta, attachments: [id, id.replace(/A$/, "B")] })).meta?.attachments, [id, id.replace(/A$/, "B")]);
        assert.equal(parseInner(buildInner("hi", meta)).meta?.attachments, undefined);
        assert.equal(parseInner(buildInner("", { ...meta, attachments: [id] })).text, "", "files without text");
    });

    it("rejects malformed lists", () => {
        assert.throws(() => buildInner("hi", { ...meta, attachments: ["short"] }), /attachment list/);
        assert.throws(() => buildInner("hi", { ...meta, attachments: Array(11).fill(id) }), /attachment list/);
        const forged = new TextEncoder().encode(`hi\n-- dcpgp/1;s=${IDS.alice};c=${IDS.dm};r=${IDS.bob};t=1;a=not valid;p=`);
        assert.equal(parseInner(forged).meta, null);
    });
});

describe("Encrypted attachments: the file itself", () => {
    it("Bob opens it, sees the name and Alice's signature; an outsider can't", async () => {
        const [alice, bob, rsa] = await Promise.all([gpgKey("alice"), gpgKey("bob"), gpgKey("rsa")]);
        const plain = new Uint8Array(300_000).map((_, i) => i % 251);
        const sealed = await encryptFileSigned(plain, "holiday.jpg", [bob.toPublic(), alice.toPublic()], alice);
        assert.ok(!Buffer.from(sealed).includes(Buffer.from("holiday.jpg")), "the name is encrypted too");

        const opened = await decryptFileVerified(sealed, [bob], [alice.toPublic()]);
        assert.equal(opened.filename, "holiday.jpg");
        assert.deepEqual(opened.data, plain);
        assert.equal(opened.signature.status, "valid");
        assert.equal(opened.signature.signerFingerprint, fingerprintOf(alice));

        await assert.rejects(decryptFileVerified(sealed, [rsa], [alice.toPublic()]), NotForUsError);
        const flipped = sealed.slice();
        flipped[flipped.length - 40] ^= 1;
        await assert.rejects(decryptFileVerified(flipped, [bob], [alice.toPublic()]), "a changed file does not open");
    });
});
