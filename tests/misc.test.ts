/*
 * DcPgp – safety number, passphrase, strength, contacts, recipients
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { acceptPendingKey, addOrReplaceContact, classifyIncomingKey, markKeyChange, validateIncomingKey } from "../core/contacts";
import { emptyVaultData } from "../core/model";
import { generatePassphrase, parseWordlist, passphraseEntropyBits } from "../core/passphrase";
import { armorKey, minimalPublicKey, PgpUserError } from "../core/pgp";
import { formatSafetyNumber, safetyNumber } from "../core/safetyNumber";
import { planRecipients } from "../core/send";
import { checkStrength } from "../core/strength";
import { fixture, gpgKey, IDS } from "./helpers";

const words = parseWordlist(readFileSync(join(import.meta.dirname, "..", "core", "wordlist-en.txt"), "utf8"));

describe("Safety number", () => {
    it("is the same for both sides, 60 digits, bound to key and id", () => {
        const a = { fpr: "E07AB410B3A497D434EAA1535517D9D61D4B8FC8", userId: IDS.alice };
        const b = { fpr: "3B1D9B52ED2AC6B7562979091C0FDE760FEBD5B0", userId: IDS.bob };
        const ab = safetyNumber(a, b);
        assert.equal(ab, safetyNumber(b, a));
        assert.match(ab, /^\d{60}$/);
        assert.equal(formatSafetyNumber(ab).length, 12);
        assert.notEqual(ab, safetyNumber(a, { ...b, userId: IDS.carol }));
        assert.notEqual(ab, safetyNumber(a, { ...b, fpr: "3B1D9B52ED2AC6B7562979091C0FDE760FEBD5B1" }));
    });
});

describe("Passwords", () => {
    it("wordlist: EFF large list without its 4 hyphenated words, 5 words ≈ 64 bits", () => {
        assert.equal(words.length, 7772);
        assert.ok(words.every(w => /^[a-z]+$/.test(w)), "no separators inside words");
        assert.ok(passphraseEntropyBits(words) > 64);
        const p = generatePassphrase(words);
        assert.equal(p.split("-").length, 5);
        assert.notEqual(p, generatePassphrase(words));
    });

    it("rejects weak passwords and phrases, accepts random words", async () => {
        const weak = ["password123", "i-love-my-cat", "sun-moon-stars-sky", "Summer2026!", "qwertyuiop", "aaaaaaaaaaaaaaaaaaaaaaa",
            "x7#Kq9!vLm2@", "Algoni2026Discord!", "correct-horse-battery-staple", "happy-birthday-to-you",
            "Passwort123", "ich-liebe-meine-katze"];
        for (const pw of weak) {
            const r = await checkStrength(pw, words, ["Algoni"]);
            assert.equal(r.ok, false, `"${pw}" must not be enough (${r.bits.toFixed(1)} bits)`);
        }
        for (const four of ["abacus-unworn-glimmer-reptile", "dwelling-skimpily-oxidize-banjo", "zestfully-baffle-unlined-sputter"]) {
            const r = await checkStrength(four, words);
            assert.equal(r.ok, true, `4 random words "${four}" must be enough (${r.bits.toFixed(1)} bits)`);
        }
        const generated = generatePassphrase(words);
        assert.equal((await checkStrength(generated, words, [], generated)).ok, true);
        assert.equal((await checkStrength("x7#Kq9!vLm2@Rt5$", words)).ok, true, "16 random characters are enough");
        const r = await checkStrength("password123", words);
        assert.ok(r.crackTime.length > 0);
    });

    it("scores words joined by separators one by one (zxcvbn must not count \"sun-moon-\" as random characters)", async () => {
        const r = await checkStrength("sun-moon-stars-sky", words);
        assert.ok(r.bits < 45, `common words stay cheap (${r.bits.toFixed(1)} bits)`);
    });
});

describe("Contacts", () => {
    it("classifies incoming keys correctly", async () => {
        const [alice, bob, rsa] = await Promise.all([gpgKey("alice"), gpgKey("bob"), gpgKey("rsa")]);
        const data = emptyVaultData({ publicKey: armorKey(await minimalPublicKey(alice)), fpr: alice.getFingerprint().toUpperCase(), createdAt: 0 });
        const incomingBob = await validateIncomingKey(armorKey(await minimalPublicKey(bob)));
        const incomingRsa = await validateIncomingKey(armorKey(await minimalPublicKey(rsa)));
        const incomingAlice = await validateIncomingKey(fixture("gpg-alice.pub.asc"));

        assert.deepEqual(classifyIncomingKey(incomingBob.fpr, IDS.bob, data), { state: "new" });
        addOrReplaceContact(data, IDS.bob, "Bob", incomingBob);
        assert.deepEqual(classifyIncomingKey(incomingBob.fpr, IDS.bob, data), { state: "same" });
        assert.equal(classifyIncomingKey(incomingRsa.fpr, IDS.bob, data).state, "changed");
        assert.deepEqual(classifyIncomingKey(incomingBob.fpr, IDS.carol, data), { state: "belongs-to-other", otherUserId: IDS.bob, otherName: "Bob" });
        assert.deepEqual(classifyIncomingKey(incomingAlice.fpr, IDS.carol, data), { state: "own-key" });

        data.contacts[IDS.bob].verified = true;
        markKeyChange(data, IDS.bob, incomingRsa, "999");
        assert.equal(data.contacts[IDS.bob].pendingKey?.fpr, incomingRsa.fpr);
        const plan = planRecipients([{ userId: IDS.bob, name: "Bob", contact: data.contacts[IDS.bob] }], {}, IDS.alice);
        assert.deepEqual(plan.missing.map(m => m.reason), ["key-changed"], "a key change pauses encryption");

        const accepted = acceptPendingKey(data, IDS.bob)!;
        assert.equal(accepted.fpr, incomingRsa.fpr);
        assert.equal(accepted.verified, false, "the new key is no longer verified");
        assert.equal(accepted.history[0].fpr, incomingBob.fpr, "the old key stays for old messages");
    });

    it("rejects invalid keys", async () => {
        await assert.rejects(validateIncomingKey(fixture("gpg-rsa-noenc.pub.asc")), PgpUserError);
    });

    it("plans recipients: without a key, blocked, duplicate, oneself", () => {
        const c = (id: string) => ({ userId: id, name: id, publicKey: "", fpr: id, verified: false, addedAt: 0, history: [] });
        const plan = planRecipients([
            { userId: IDS.alice, name: "me", contact: null },
            { userId: IDS.bob, name: "Bob", contact: c(IDS.bob) },
            { userId: IDS.bob, name: "Bob", contact: c(IDS.bob) },
            { userId: IDS.carol, name: "Carol", contact: null },
            { userId: IDS.other, name: "X", contact: c(IDS.other) }
        ], { [IDS.other]: 1 }, IDS.alice);
        assert.deepEqual(plan.readers.map(r => r.userId), [IDS.bob]);
        assert.deepEqual(plan.missing.map(m => [m.userId, m.reason]), [[IDS.carol, "no-key"], [IDS.other, "blocked"]]);
    });
});
