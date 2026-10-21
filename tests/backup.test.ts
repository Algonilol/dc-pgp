/*
 * DcPgp – portable vault backup, setup requirements and mode changes
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { BackupPasswordError, createBackup, openBackup, parseBackupFile } from "../core/backup";
import { utf8 } from "../core/bytes";
import { emptyVaultData } from "../core/model";
import { armorKey, fingerprintOf, minimalPublicKey, readPrivateKey } from "../core/pgp";
import {
    createVault, makeSlotA, openWithPassword, openWithPrivateKey, recoverRawDek, sealVault, VaultCorruptError
} from "../core/vault";
import { decodeKeyFile, fileWithHeader, headerForMode, privateKeyOptions, setupNeeds, withoutPrivateKeys, withPrivateKey } from "../core/vaultOps";
import { argon2, FAST_PARAMS, fixture, gpgKey, IDS, makeMixer } from "./helpers";

async function storedData() {
    const alice = await gpgKey("alice");
    const pub = await minimalPublicKey(alice);
    const data = emptyVaultData({ publicKey: armorKey(pub), fpr: fingerprintOf(alice), createdAt: 1, privateKey: armorKey(alice) });
    data.channels[IDS.dm] = { encrypt: true, since: 5 };
    data.oldKeys.push({ publicKey: "old", fpr: "OLD", retiredAt: 2, privateKey: "old-secret" });
    return { alice, pub, data };
}

describe("Vault backup", () => {
    it("restores the content with the backup password, also without the device key", async () => {
        const { data } = await storedData();
        const text = await createBackup({ owner: IDS.alice, mode: "stored", data, password: "backup-password-long", params: FAST_PARAMS, argon2, now: 7 });
        assert.ok(!text.includes("PRIVATE KEY"), "no plaintext in the backup");
        const restored = await openBackup(text, "backup-password-long", argon2);
        assert.equal(restored.owner, IDS.alice);
        assert.equal(restored.mode, "stored");
        assert.equal(restored.created, 7);
        assert.equal(restored.data.channels[IDS.dm].encrypt, true);
        assert.match(restored.data.self.privateKey!, /PRIVATE KEY/);
    });

    it("rejects a wrong password and modified files", async () => {
        const { data } = await storedData();
        const text = await createBackup({ owner: IDS.alice, mode: "stored", data, password: "backup-password-long", params: FAST_PARAMS, argon2 });
        await assert.rejects(openBackup(text, "wrong", argon2), BackupPasswordError);
        const f = JSON.parse(text);
        await assert.rejects(openBackup(JSON.stringify({ ...f, owner: IDS.bob }), "backup-password-long", argon2), BackupPasswordError, "the header is bound");
        await assert.rejects(openBackup(JSON.stringify({ ...f, mode: "ram" }), "backup-password-long", argon2), BackupPasswordError);
        assert.throws(() => parseBackupFile("not json"), VaultCorruptError);
        assert.throws(() => parseBackupFile(JSON.stringify({ ...f, type: "x" })), VaultCorruptError);
        assert.throws(() => parseBackupFile(JSON.stringify({ ...f, kdf: { ...f.kdf, m: 1 } })), /Argon2/);
    });

    it("a \"Stored\" backup without a private key counts as damaged", async () => {
        const { data } = await storedData();
        const text = await createBackup({ owner: IDS.alice, mode: "stored", data: withoutPrivateKeys(data), password: "backup-password-long", params: FAST_PARAMS, argon2 });
        await assert.rejects(openBackup(text, "backup-password-long", argon2), VaultCorruptError);
        const ram = await createBackup({ owner: IDS.alice, mode: "ram", data: withoutPrivateKeys(data), password: "backup-password-long", params: FAST_PARAMS, argon2 });
        assert.equal((await openBackup(ram, "backup-password-long", argon2)).data.self.privateKey, undefined);
    });
});

describe("Setup and mode changes", () => {
    it("knows when a password and a key file are needed", () => {
        assert.deepEqual(setupNeeds("import", "stored"), { password: true, keyFile: false });
        assert.deepEqual(setupNeeds("import", "ram"), { password: false, keyFile: false });
        assert.deepEqual(setupNeeds("generate", "stored"), { password: true, keyFile: true });
        assert.deepEqual(setupNeeds("generate", "ram"), { password: true, keyFile: true });
    });

    it("removes and adds private keys without changing the original", async () => {
        const { data } = await storedData();
        const ram = withoutPrivateKeys(data);
        assert.equal(ram.self.privateKey, undefined);
        assert.equal(ram.oldKeys[0].privateKey, undefined);
        assert.ok(data.self.privateKey, "original unchanged");
        assert.equal(withPrivateKey(ram, "X").self.privateKey, "X");
    });

    it("Stored → RAM only → Stored", async () => {
        const { alice, pub, data } = await storedData();
        const mixer = makeMixer();
        const { file, dek } = await createVault({ mode: "stored", owner: IDS.alice, ownPublicKey: pub, data, password: "first-password-long", params: FAST_PARAMS, argon2, mixer });

        const ramFile = await sealVault(headerForMode(file, "ram"), dek, withoutPrivateKeys(data));
        assert.equal(ramFile.mode, "ram");
        assert.equal(ramFile.a, undefined);
        await assert.rejects(openWithPassword(ramFile, "first-password-long", argon2, mixer), /no password access/);
        const openedRam = await openWithPrivateKey(ramFile, alice);
        assert.equal(openedRam.data.self.privateKey, undefined);

        const raw = await recoverRawDek(ramFile, alice);
        const slot = await makeSlotA(raw, "second-password-long", FAST_PARAMS, argon2, mixer);
        const storedFile = await sealVault(headerForMode(ramFile, "stored", slot), dek, withPrivateKey(openedRam.data, armorKey(alice)));
        const reopened = await openWithPassword(storedFile, "second-password-long", argon2, mixer);
        assert.equal(fingerprintOf(await readPrivateKey(reopened.data.self.privateKey!)), fingerprintOf(alice));
        assert.throws(() => headerForMode(ramFile, "stored"), /needs a password/);

        const swapped = fileWithHeader(file, headerForMode(file, "ram"));
        assert.equal(swapped.mode, "ram");
        assert.equal(swapped.a, undefined, "the old password access is gone");
        assert.equal(swapped.ct, file.ct);
    });

    it("settings: show and remove the stored key only in \"Stored\" mode, store it again in \"RAM only\"", () => {
        assert.deepEqual(privateKeyOptions(true, "stored"), { show: true, remove: true, store: false });
        assert.deepEqual(privateKeyOptions(true, "ram"), { show: false, remove: false, store: true },
            "no vault password to confirm in RAM only mode");
        assert.deepEqual(privateKeyOptions(false, "stored"), { show: false, remove: false, store: false }, "nothing while locked");
        assert.deepEqual(privateKeyOptions(true, undefined), { show: false, remove: false, store: false });
    });

    it("recognises armored and binary key files", () => {
        const armored = fixture("gpg-alice.sec.asc");
        assert.equal(typeof decodeKeyFile(utf8(armored)), "string");
        const binary = new Uint8Array([0x95, 0x01, 0x02, 0x03]);
        assert.equal(decodeKeyFile(binary), binary);
    });
});
