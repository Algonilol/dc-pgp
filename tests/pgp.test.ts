/*
 * DcPgp – OpenPGP layer tests against real GnuPG (Kleopatra) keys
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import * as openpgp from "openpgp";

import { utf8 } from "../core/bytes";
import {
    decryptVerified, decryptWithKeys, encryptSigned, encryptToKeys, exportProtectedPrivateKey, fingerprintOf, generatePrivateKey,
    inspectKey, minimalPublicKey, NotForUsError, PgpUserError, readPrivateKey, readPublicKey, unlockPrivateKey
} from "../core/pgp";
import { fixture, GPG_PASSPHRASE, gpgKey } from "./helpers";

describe("Keys from Kleopatra/GnuPG", () => {
    it("reads a protected Curve25519 key with its passphrase", async () => {
        const key = await gpgKey("alice");
        assert.ok(key.isDecrypted());
        assert.equal(fingerprintOf(key), "E07AB410B3A497D434EAA1535517D9D61D4B8FC8");
    });

    it("reports a wrong passphrase in plain words", async () => {
        const key = await readPrivateKey(fixture("gpg-alice.sec.asc"));
        await assert.rejects(unlockPrivateKey(key, "wrong"), (e: Error) => e instanceof PgpUserError && e.message === "Wrong passphrase.");
    });

    it("rejects a public key where a private key is needed", async () => {
        await assert.rejects(readPrivateKey(fixture("gpg-alice.pub.asc")), (e: Error) => e instanceof PgpUserError && /no private key/.test(e.message));
    });

    it("rejects garbage", async () => {
        await assert.rejects(readPrivateKey("hello world"), PgpUserError);
        await assert.rejects(readPublicKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----"), PgpUserError);
    });

    it("inspects keys: Curve25519 without warnings, email and RSA with warnings, missing subkey as error", async () => {
        const alice = await inspectKey(await gpgKey("alice"));
        assert.deepEqual(alice.errors, []);
        assert.deepEqual(alice.warnings, []);
        assert.equal(alice.algorithm, "Ed25519");
        assert.equal(alice.encryptionAlgorithm, "Curve25519");

        const bob = await inspectKey(await gpgKey("bob"));
        assert.deepEqual(bob.errors, []);
        assert.ok(bob.warnings.some(w => /email address/.test(w)));

        const rsa = await inspectKey(await gpgKey("rsa"));
        assert.deepEqual(rsa.errors, []);
        assert.ok(rsa.warnings.some(w => /RSA/.test(w)));

        const noEnc = await inspectKey(await readPublicKey(fixture("gpg-rsa-noenc.pub.asc")));
        assert.ok(noEnc.errors.some(e => /encryption subkey/.test(e)));
    });

    it("shrinks the own key for the exchange", async () => {
        const alice = await gpgKey("alice");
        const minimal = await minimalPublicKey(alice);
        assert.equal(minimal.users.length, 1);
        assert.equal(minimal.subkeys.length, 1);
        assert.equal(fingerprintOf(minimal), fingerprintOf(alice));
        await minimal.verifyPrimaryKey();
        const reread = await readPublicKey(minimal.armor());
        assert.equal(fingerprintOf(reread), fingerprintOf(alice));
        assert.ok(minimal.armor().length < 700, "a Curve25519 key fits easily into one message");
    });
});

describe("Encryption with hidden recipients", () => {
    it("Bob decrypts and checks Alice's signature; strangers can't", async () => {
        const alice = await gpgKey("alice");
        const bob = await gpgKey("bob");
        const rsa = await gpgKey("rsa");
        const armored = await encryptSigned(utf8("Hello Bob äöü 🔒"), [bob.toPublic(), alice.toPublic()], alice);

        const msg = await openpgp.readMessage({ armoredMessage: armored });
        const pkesks = msg.packets.filter(p => (p.constructor as any).tag === openpgp.enums.packet.publicKeyEncryptedSessionKey) as any[];
        assert.equal(pkesks.length, 2);
        assert.ok(pkesks.every(p => p.publicKeyID.isWildcard()), "key ids are hidden");

        const res = await decryptVerified(armored, [bob], [alice.toPublic()]);
        assert.equal(new TextDecoder().decode(res.data), "Hello Bob äöü 🔒");
        assert.equal(res.signature.status, "valid");
        assert.equal(res.signature.signerFingerprint, fingerprintOf(alice));

        await assert.rejects(decryptVerified(armored, [rsa], []), NotForUsError);
    });

    it("detects unknown signing keys and missing signatures", async () => {
        const alice = await gpgKey("alice");
        const bob = await gpgKey("bob");
        const armored = await encryptSigned(utf8("x"), [bob.toPublic()], alice);
        const unknown = await decryptVerified(armored, [bob], [bob.toPublic()]);
        assert.equal(unknown.signature.status, "unknown-key");

        const unsigned = await encryptToKeys(utf8("y"), [bob.toPublic()]);
        const missing = await decryptVerified(unsigned, [bob], [alice.toPublic()]);
        assert.equal(missing.signature.status, "missing");
    });

    it("tells tampered messages apart from \"not for you\"", async () => {
        const alice = await gpgKey("alice");
        const bob = await gpgKey("bob");
        const armored = await encryptSigned(utf8("secret ".repeat(20)), [bob.toPublic()], alice);
        const body = armored.split("\n").filter(l => l && !l.startsWith("-----") && !l.startsWith("=")).join("");
        const bytes = Buffer.from(body, "base64");
        for (const offset of [40, 80, 30]) {
            const copy = Buffer.from(bytes);
            copy[copy.length - offset] ^= 0x01;
            const b64 = copy.toString("base64").match(/.{1,64}/g)!.join("\n");
            const tampered = `-----BEGIN PGP MESSAGE-----\n\n${b64}\n-----END PGP MESSAGE-----\n`;
            await assert.rejects(decryptVerified(tampered, [bob], [alice.toPublic()]), (e: Error) => !(e instanceof NotForUsError), `byte -${offset}`);
        }
    });

    it("reads a message created by GnuPG with a hidden recipient", async () => {
        const alice = await gpgKey("alice");
        const bob = await gpgKey("bob");
        const res = await decryptVerified(fixture("gpg-alice-to-bob.asc"), [bob], [alice.toPublic()]);
        assert.equal(new TextDecoder().decode(res.data), fixture("gpg-alice-to-bob.txt"));
        assert.equal(res.signature.status, "valid");
    });

    it("rejects too many recipient entries (protection against slowdown attacks)", async () => {
        const bob = await gpgKey("bob");
        const keys = await Promise.all(Array.from({ length: 101 }, () => openpgp.generateKey({ userIDs: [{ name: "x" }], format: "object" }).then(k => k.publicKey)));
        const armored = await encryptToKeys(utf8("z"), keys);
        await assert.rejects(decryptVerified(armored, [bob], []), /Too many recipient entries/);
    });
});

describe("Generated keys", () => {
    it("are v4 Curve25519 without the AEAD feature (Kleopatra compatible) and exportable as a protected file", async () => {
        const key = await generatePrivateKey("Algoni");
        assert.equal(key.keyPacket.version, 4);
        assert.deepEqual(key.getAlgorithmInfo(), { algorithm: "eddsaLegacy", curve: "ed25519Legacy" });
        const primary = await key.getPrimaryUser();
        const features: number[] = Array.from(primary.selfCertification.features ?? []);
        assert.ok(features.every(f => (f & 0x08) === 0), "no SEIPDv2 feature");
        const report = await inspectKey(key);
        assert.deepEqual(report.errors, []);
        assert.ok(report.expires && report.expires.getTime() > Date.now() + 700 * 24 * 3600 * 1000);

        const backup = await exportProtectedPrivateKey(key, "correct-horse-battery-staple");
        assert.match(backup, /BEGIN PGP PRIVATE KEY BLOCK/);
        const reread = await readPrivateKey(backup);
        assert.equal(reread.isDecrypted(), false);
        await assert.rejects(unlockPrivateKey(reread, "wrong"), PgpUserError);
        const unlocked = await unlockPrivateKey(reread, "correct-horse-battery-staple");
        assert.equal(fingerprintOf(unlocked), fingerprintOf(key));
        assert.ok(key.isDecrypted(), "exporting does not change the key in memory");
    });
});

describe("Recovery copy (slot B)", () => {
    it("encrypts bytes to the own key", async () => {
        const alice = await gpgKey("alice");
        const bob = await gpgKey("bob");
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const armored = await encryptToKeys(secret, [alice.toPublic()]);
        assert.deepEqual(await decryptWithKeys(armored, [alice]), secret);
        await assert.rejects(decryptWithKeys(armored, [bob]), NotForUsError);
    });
});

void GPG_PASSPHRASE;
