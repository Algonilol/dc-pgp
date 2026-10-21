/*
 * DcPgp – vault tests
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { emptyVaultData, normalizeVaultData, pruneVaultData } from "../core/model";
import { armorKey, fingerprintOf, minimalPublicKey, NotForUsError } from "../core/pgp";
import {
    createVault, headerOf, makeSlotA, openWithPassword, openWithPrivateKey, recoverRawDek, sealVault,
    validateVaultFile, VaultCorruptError, WrongPasswordError
} from "../core/vault";
import { argon2, FAST_PARAMS, gpgKey, IDS, makeMixer } from "./helpers";

async function setup(mode: "stored" | "ram" = "stored") {
    const alice = await gpgKey("alice");
    const pub = await minimalPublicKey(alice);
    const data = emptyVaultData({ publicKey: armorKey(pub), fpr: fingerprintOf(alice), createdAt: 1, ...(mode === "stored" ? { privateKey: armorKey(alice) } : {}) });
    data.channels[IDS.dm] = { encrypt: true, since: 5 };
    const mixer = makeMixer();
    const { file, dek } = await createVault({ mode, owner: IDS.alice, ownPublicKey: pub, data, password: "correct-password-here", params: FAST_PARAMS, argon2, mixer });
    return { alice, pub, data, mixer, file, dek };
}

describe("Vault", () => {
    it("opens with password plus device key", async () => {
        const { file, mixer } = await setup();
        assert.equal(file.a?.device, true);
        const open = await openWithPassword(validateVaultFile(JSON.parse(JSON.stringify(file))), "correct-password-here", argon2, mixer);
        assert.equal(open.data.channels[IDS.dm].encrypt, true);
        assert.ok(open.data.self.privateKey?.includes("PRIVATE KEY"));
    });

    it("rejects a wrong password and a foreign device key", async () => {
        const { file, mixer } = await setup();
        await assert.rejects(openWithPassword(file, "wrong-password-here", argon2, mixer), WrongPasswordError);
        await assert.rejects(openWithPassword(file, "correct-password-here", argon2, makeMixer()), WrongPasswordError, "another PC = another device key");
        await assert.rejects(openWithPassword(file, "correct-password-here", argon2, null), /Device key/);
    });

    it("opens with the own key (slot B), also after a forgotten password", async () => {
        const { file, alice } = await setup();
        const open = await openWithPrivateKey(file, alice);
        assert.equal(open.data.self.fpr, fingerprintOf(alice));
        await assert.rejects(openWithPrivateKey(file, await gpgKey("bob")), NotForUsError);
    });

    it("detects tampering with content and header", async () => {
        const { file, mixer } = await setup();
        const flipped = { ...file, ct: file.ct.slice(0, 10) + (file.ct[10] === "A" ? "B" : "A") + file.ct.slice(11) };
        await assert.rejects(openWithPassword(flipped, "correct-password-here", argon2, mixer), VaultCorruptError);
        const swapped = { ...file, owner: IDS.bob };
        await assert.rejects(openWithPassword(swapped, "correct-password-here", argon2, mixer), VaultCorruptError);
        assert.throws(() => validateVaultFile({ v: 2 }), VaultCorruptError);
        await assert.rejects(openWithPassword({ ...file, a: { ...file.a!, kdf: { ...file.a!.kdf, m: 1 } } }, "x", argon2, mixer), /Argon2/);
    });

    it("\"RAM only\" mode has no password access", async () => {
        const { file, alice } = await setup("ram");
        assert.equal(file.a, undefined);
        await assert.rejects(openWithPassword(file, "correct-password-here", argon2, null), /no password access/);
        const open = await openWithPrivateKey(file, alice);
        assert.equal(open.data.self.privateKey, undefined);
    });

    it("saves changes with a new IV and changes the password without a new data key", async () => {
        const { file, dek, alice, mixer } = await setup();
        const open = await openWithPrivateKey(file, alice);
        open.data.channels[IDS.other] = { encrypt: true };
        const resealed = await sealVault(headerOf(file), dek, open.data);
        assert.notEqual(resealed.iv, file.iv);

        const raw = await recoverRawDek(resealed, alice);
        const newA = await makeSlotA(raw, "new-password-quite-long", FAST_PARAMS, argon2, mixer);
        const withNewPassword = await sealVault({ ...headerOf(resealed), a: newA }, dek, open.data);
        await assert.rejects(openWithPassword(withNewPassword, "correct-password-here", argon2, mixer), WrongPasswordError);
        const reopened = await openWithPassword(withNewPassword, "new-password-quite-long", argon2, mixer);
        assert.equal(reopened.data.channels[IDS.other].encrypt, true);
    });
});

describe("Changing the password with a fresh data key", () => {
    it("neither the old password nor an old copy of the vault opens the new one", async () => {
        const { file: oldFile, data, pub, mixer } = await setup();
        const { file: newFile } = await createVault({ mode: "stored", owner: IDS.alice, ownPublicKey: pub, data, password: "new-password-quite-long", params: FAST_PARAMS, argon2, mixer });
        await assert.rejects(openWithPassword(newFile, "correct-password-here", argon2, mixer), WrongPasswordError);
        // An old copy's password slot still unwraps the old data key, which no longer fits the new content.
        await assert.rejects(openWithPassword({ ...newFile, a: oldFile.a }, "correct-password-here", argon2, mixer), VaultCorruptError);
        const reopened = await openWithPassword(newFile, "new-password-quite-long", argon2, mixer);
        assert.equal(reopened.data.channels[IDS.dm].encrypt, true);
    });
});

describe("Vault data", () => {
    it("normalises and drops garbage", () => {
        const data = normalizeVaultData({
            self: { publicKey: "k", fpr: "F" },
            contacts: { [IDS.bob]: { publicKey: "b", fpr: "B", verified: "yes" }, "not-a-snowflake": { publicKey: "x", fpr: "y" } },
            channels: { [IDS.dm]: { encrypt: true, target: { kind: "role", roleId: "nope" } } },
            handled: { [IDS.other]: { at: 1, result: "hack" } },
            __proto__: { polluted: true }
        });
        assert.deepEqual(Object.keys(data.contacts), [IDS.bob]);
        assert.equal(data.contacts[IDS.bob].verified, false);
        assert.equal(data.channels[IDS.dm].target, undefined);
        assert.deepEqual(data.handled, {});
        assert.throws(() => normalizeVaultData({}), /damaged/);
    });

    it("keeps the key lifetime fields", () => {
        const data = normalizeVaultData({
            self: { publicKey: "k", fpr: "F", renewedAt: 5 },
            contacts: {
                [IDS.bob]: { publicKey: "b", fpr: "B", keyExpires: 7, sentKeyAt: 3 },
                [IDS.carol]: { publicKey: "c", fpr: "C", keyExpires: null, sentKeyAt: "x" },
                [IDS.other]: { publicKey: "o", fpr: "O", keyExpires: "soon", pendingKey: { publicKey: "p", fpr: "P", keyExpires: 9 } }
            }
        });
        assert.equal(data.self.renewedAt, 5);
        assert.equal(data.contacts[IDS.bob].keyExpires, 7);
        assert.equal(data.contacts[IDS.bob].sentKeyAt, 3);
        assert.equal(data.contacts[IDS.carol].keyExpires, null, "null: never expires");
        assert.equal("sentKeyAt" in data.contacts[IDS.carol], false);
        assert.equal("keyExpires" in data.contacts[IDS.other], false, "unknown: computed again after unlocking");
        assert.equal(data.contacts[IDS.other].pendingKey?.keyExpires, 9);
    });

    it("cleans up old entries", () => {
        const data = emptyVaultData({ publicKey: "k", fpr: "F", createdAt: 0 });
        const now = 1_000 * 24 * 3600 * 1000;
        data.outgoing[IDS.bob] = { at: now - 31 * 24 * 3600 * 1000, channelId: IDS.dm };
        data.channels[IDS.other] = { encrypt: false };
        pruneVaultData(data, now);
        assert.deepEqual(data.outgoing, {});
        assert.deepEqual(data.channels, {});
    });
});
