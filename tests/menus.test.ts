/*
 * DcPgp – lock menu / user menu models and the chat switches
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { chatButtonModel, type ChatMenuInput, encryptionBlocker, type MenuEntry, setChannelAutoDecrypt, setChannelEncryption, shouldShowEncryptedDot, userMenuModel } from "../core/menus";
import { emptyVaultData } from "../core/model";
import { IDS } from "./helpers";

const base: ChatMenuInput = {
    phase: "unlocked",
    kind: "dm",
    encrypted: false,
    oneShot: false,
    autoDecrypt: true,
    hookHealthy: true,
    readers: [],
    missing: [],
    partner: { name: "Bob", status: "none", outgoingPending: false }
};

const model = (over: Partial<ChatMenuInput>) => chatButtonModel({ ...base, ...over });
const entry = (entries: MenuEntry[], id: string) => entries.find(e => e.id === id) as any;

describe("Chat switches", () => {
    it("switches on and off, the start time is kept", () => {
        const data = emptyVaultData({ publicKey: "k", fpr: "F", createdAt: 0 });
        setChannelEncryption(data, IDS.dm, true, 100);
        assert.deepEqual(data.channels[IDS.dm], { encrypt: true, since: 100 });
        setChannelEncryption(data, IDS.dm, true, 200);
        assert.equal(data.channels[IDS.dm].since, 100);
        data.channels[IDS.dm].autoDecrypt = false;
        setChannelEncryption(data, IDS.dm, false, 300);
        assert.deepEqual(data.channels[IDS.dm], { encrypt: false, autoDecrypt: false });
    });

    it("decrypt automatically: only differences from the global setting are stored", () => {
        const data = emptyVaultData({ publicKey: "k", fpr: "F", createdAt: 0 });
        setChannelAutoDecrypt(data, IDS.dm, false, true);
        assert.deepEqual(data.channels[IDS.dm], { encrypt: false, autoDecrypt: false });
        setChannelAutoDecrypt(data, IDS.dm, true, true);
        assert.deepEqual(data.channels[IDS.dm], { encrypt: false }, "back to the global value: exception removed");
        setChannelEncryption(data, IDS.other, true, 100);
        setChannelAutoDecrypt(data, IDS.other, true, false);
        assert.deepEqual(data.channels[IDS.other], { encrypt: true, since: 100, autoDecrypt: true });
    });
});

describe("Lock menu", () => {
    it("shows loading, setup, locked and not-available states", () => {
        assert.equal(model({ phase: "loading" }).icon, "unavailable");
        const nosetup = model({ phase: "nosetup" });
        assert.equal(nosetup.icon, "unavailable");
        assert.equal(entry(nosetup.entries, "setup").type, "action");
        assert.equal(model({ kind: "unsupported" }).icon, "unavailable");
        const locked = model({ phase: "locked", encrypted: true });
        assert.equal(locked.icon, "on");
        assert.ok(locked.entries.every(e => e.type !== "toggle"), "locked: nothing can be switched");
        assert.equal(entry(locked.entries, "unlock").label, "Unlock …");
        assert.equal(entry(locked.entries, "lock"), undefined);
    });

    it("the \"decrypt automatically\" switch shows the effective value", () => {
        assert.equal(entry(model({}).entries, "auto-decrypt").checked, true);
        const off = entry(model({ autoDecrypt: false, encrypted: true }).entries, "auto-decrypt");
        assert.equal(off.checked, false);
        assert.equal(off.disabled, false, "switchable even when encryption can't be turned on");
    });

    it("unlocked: \"Lock now\" is the last entry", () => {
        const m = model({ partner: { name: "Bob", status: "unverified", outgoingPending: false }, readers: [{ name: "Bob", verified: false }] });
        assert.equal(m.entries[m.entries.length - 1].id, "lock");
        assert.equal(entry(m.entries, "unlock"), undefined);
    });

    it("DM without a key: switching on is blocked, a request is offered", () => {
        const m = model({});
        assert.equal(m.icon, "off");
        assert.equal(entry(m.entries, "encrypt-all").disabled, true);
        assert.equal(entry(m.entries, "encrypt-once").disabled, true);
        assert.match(entry(m.entries, "blocker").label, /Exchange keys with Bob/);
        assert.equal(entry(m.entries, "request-key").label, "Request Bob's key");
        const pending = model({ partner: { name: "Bob", status: "none", outgoingPending: true } });
        assert.equal(entry(pending.entries, "request-key").label, "Send the key request to Bob again");
        assert.match(entry(pending.entries, "blocker").label, /Waiting for Bob's key/);
    });

    it("the partner's key is waiting: accept instead of waiting", () => {
        const m = model({ partner: { name: "Bob", status: "none", outgoingPending: true, offer: true } });
        assert.equal(entry(m.entries, "accept-key").label, "Accept Bob's key");
        assert.equal(entry(m.entries, "request-key"), undefined);
        assert.match(entry(m.entries, "blocker").label, /accept it first/);
    });

    it("DM with a contact: switchable, safety number offered", () => {
        const m = model({ partner: { name: "Bob", status: "unverified", outgoingPending: false }, readers: [{ name: "Bob", verified: false }] });
        assert.equal(entry(m.entries, "encrypt-all").disabled, false);
        assert.equal(entry(m.entries, "blocker"), undefined);
        assert.equal(entry(m.entries, "verify").label, "Compare safety number with Bob");
        assert.equal(entry(m.entries, "readers").label, "Readable by: Bob");

        const trusted = model({ encrypted: true, partner: { name: "Bob", status: "trusted", outgoingPending: false }, readers: [{ name: "Bob", verified: true }] });
        assert.equal(trusted.icon, "on");
        assert.equal(entry(trusted.entries, "encrypt-all").checked, true);
        assert.equal(entry(trusted.entries, "encrypt-once"), undefined, "\"next message only\" makes no sense when everything is encrypted");
        assert.equal(entry(trusted.entries, "readers").label, "Readable by: Bob ✓");
    });

    it("changed key: switching on is blocked, switching off allowed, review offered", () => {
        const m = model({ encrypted: true, partner: { name: "Bob", status: "changed", outgoingPending: false } });
        assert.equal(entry(m.entries, "encrypt-all").disabled, false, "switching off always works");
        assert.match(entry(m.entries, "blocker").label, /new key/);
        assert.equal(entry(m.entries, "review-change").label, "Review Bob's new key");
        assert.equal(entry(model({ partner: { name: "Bob", status: "changed", outgoingPending: false } }).entries, "encrypt-all").disabled, true);
    });

    it("broken send protection: nothing can be switched on, warning icon for an active chat", () => {
        const input = { hookHealthy: false, partner: { name: "Bob", status: "trusted" as const, outgoingPending: false }, readers: [{ name: "Bob", verified: true }] };
        assert.match(encryptionBlocker({ ...base, ...input })!, /send protection/);
        assert.equal(entry(model(input).entries, "encrypt-all").disabled, true);
        assert.equal(model({ ...input, encrypted: true }).icon, "warning");
    });

    it("server channel whose viewers cannot be checked: encryption paused, warning icon, no dot", () => {
        const input = { kind: "guild" as const, partner: undefined, visibilityUnknown: true };
        assert.match(encryptionBlocker({ ...base, ...input })!, /who can see this channel/);
        assert.equal(entry(model(input).entries, "encrypt-all").disabled, true);
        assert.equal(model({ ...input, encrypted: true }).icon, "warning");
        assert.equal(entry(model({ ...input, encrypted: true }).entries, "encrypt-all").disabled, false, "switching off stays possible");
    });

    it("group/server: readers and who has no key", () => {
        const m = model({ kind: "guild", partner: undefined, readers: [{ name: "A", verified: true }, { name: "B", verified: false }], missing: [{ name: "C", reason: "no-key" }] });
        assert.equal(entry(m.entries, "encrypt-all").disabled, false);
        assert.equal(entry(m.entries, "readers").label, "Readable by: A ✓, B");
        assert.equal(entry(m.entries, "missing").label, "Not readable for: C (no key)");
        const reasons = model({ kind: "group", partner: undefined, missing: [{ name: "D", reason: "blocked" }, { name: "E", reason: "key-changed" }, { name: "F", reason: "key-expired" }] });
        assert.equal(entry(reasons.entries, "missing").label, "Not readable for: D (blocked), E (new key not confirmed), F (key expired)");
        const many = model({ kind: "group", partner: undefined, missing: "CDEFGHI".split("").map(name => ({ name, reason: "no-key" as const })) });
        assert.equal(entry(many.entries, "missing").label, "Not readable for: C (no key), D (no key), E (no key), F (no key), G (no key) and 2 more");
        assert.equal(entry(model({ kind: "group", partner: undefined }).entries, "encrypt-all").disabled, true);
    });

    it("\"next message only\" shows the active lock", () => {
        const m = model({ oneShot: true, partner: { name: "Bob", status: "unverified", outgoingPending: false }, readers: [{ name: "Bob", verified: false }] });
        assert.equal(m.icon, "on");
        assert.equal(entry(m.entries, "encrypt-once").checked, true);
    });
});

describe("Removing a contact from the lock menu", () => {
    const bob = (over: Partial<NonNullable<ChatMenuInput["partner"]>> = {}) => ({ name: "Bob", status: "unverified" as const, outgoingPending: false, ...over });

    it("is offered in a DM with a stored key or a waiting key message", () => {
        const m = model({ partner: bob({ hasContact: true }), readers: [{ name: "Bob", verified: false }] });
        const remove = entry(m.entries, "remove-contact");
        assert.equal(remove.type, "action");
        assert.equal(remove.danger, true);
        assert.equal(m.entries[m.entries.length - 1].id, "lock", "\"Lock now\" stays last");
        assert.ok(entry(model({ partner: bob({ status: "none", outgoingPending: true, offer: true }) }).entries, "remove-contact"));
        assert.ok(entry(model({ partner: bob({ status: "blocked", hasContact: true }) }).entries, "remove-contact"), "also when blocked");
    });

    it("is not offered without a key, in groups or while locked", () => {
        assert.equal(entry(model({}).entries, "remove-contact"), undefined);
        assert.equal(entry(model({ kind: "group", partner: undefined }).entries, "remove-contact"), undefined);
        assert.equal(entry(model({ phase: "locked", partner: bob({ hasContact: true }) }).entries, "remove-contact"), undefined);
    });
});

describe("Encrypted dot on the lock button", () => {
    it("only for an unlocked, encrypted chat", () => {
        assert.equal(shouldShowEncryptedDot("unlocked", true, true), true);
        assert.equal(shouldShowEncryptedDot("unlocked", false, true), false);
        assert.equal(shouldShowEncryptedDot("locked", true, true), false, "locked: nothing can be sent encrypted");
        assert.equal(shouldShowEncryptedDot("locked", false, true), false);
    });

    it("not while loading or before setup", () => {
        assert.equal(shouldShowEncryptedDot("loading", true, true), false);
        assert.equal(shouldShowEncryptedDot("nosetup", true, true), false);
    });

    it("not while the send protection is broken, even when unlocked and encrypted", () => {
        assert.equal(shouldShowEncryptedDot("unlocked", true, false), false, "no \"will be sent encrypted\" promise with a broken hook");
        assert.equal(shouldShowEncryptedDot("unlocked", false, false), false);
        assert.equal(shouldShowEncryptedDot("locked", true, false), false);
    });
});

describe("User menu", () => {
    const ids = (status: Parameters<typeof userMenuModel>[0], hasContact = false, outgoingPending = false) =>
        userMenuModel(status, { hasContact, outgoingPending }).map(e => e.id);

    it("offers the right actions for each status", () => {
        assert.deepEqual(ids("none"), ["request-key", "block"]);
        assert.equal(userMenuModel("none", { hasContact: false, outgoingPending: true })[0].label, "Send key request again");
        assert.deepEqual(ids("unverified", true), ["verify", "block", "remove"]);
        assert.deepEqual(ids("trusted", true), ["verify", "block", "remove"]);
        assert.deepEqual(ids("changed", true), ["review-change", "block", "remove"]);
        assert.deepEqual(ids("blocked"), ["unblock"]);
        assert.deepEqual(ids("blocked", true), ["unblock", "remove"]);
    });

    it("offers the updated key when the stored one runs out", () => {
        const expiring = userMenuModel("trusted", { hasContact: true, outgoingPending: false, keyExpiring: true });
        assert.deepEqual(expiring.map(e => e.id), ["request-update", "verify", "block", "remove"]);
        assert.equal(expiring[0].label, "Request updated key");
    });
});

describe("Expiring keys in the lock menu", () => {
    const partner = { name: "Bob", status: "trusted" as const, outgoingPending: false, hasContact: true };

    it("offers to request the updated key 30 days ahead", () => {
        assert.equal(entry(model({ partner }).entries, "request-update"), undefined);
        const expiring = model({ partner: { ...partner, keyExpiring: true } });
        assert.equal(entry(expiring.entries, "request-update").label, "Request Bob's updated key");
        assert.equal(entry(expiring.entries, "encrypt-all").disabled, false, "still usable until it has expired");
    });

    it("blocks switching encryption on once it has expired", () => {
        const expired = { ...base, partner: { ...partner, keyExpiring: true, keyExpired: true } };
        assert.equal(encryptionBlocker(expired), "Bob's key has expired – request the updated key.");
        assert.equal(entry(chatButtonModel(expired).entries, "encrypt-all").disabled, true);
    });
});
