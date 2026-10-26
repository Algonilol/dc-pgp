/*
 * DcPgp – auto-lock decisions
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { shouldAutoLock, shouldLockOnPowerEvent, shouldUnlockOnPowerEvent } from "../core/idle";

describe("Auto-lock after inactivity", () => {
    it("locks once the idle time reaches the setting", () => {
        assert.equal(shouldAutoLock(3600, 60, "unlocked"), true, "exactly the limit");
        assert.equal(shouldAutoLock(5000, 60, "unlocked"), true);
        assert.equal(shouldAutoLock(3599, 60, "unlocked"), false, "one second short");
        assert.equal(shouldAutoLock(0, 15, "unlocked"), false);
    });

    it("never locks when switched off or the setting is invalid", () => {
        assert.equal(shouldAutoLock(1e9, 0, "unlocked"), false, "0 = never");
        assert.equal(shouldAutoLock(1e9, -5, "unlocked"), false);
        assert.equal(shouldAutoLock(1e9, Number.NaN, "unlocked"), false);
    });

    it("ignores unusable idle times", () => {
        assert.equal(shouldAutoLock(Number.NaN, 15, "unlocked"), false);
        assert.equal(shouldAutoLock(Number.POSITIVE_INFINITY, 15, "unlocked"), false);
    });

    it("only acts while unlocked", () => {
        for (const phase of ["locked", "nosetup", "loading"] as const)
            assert.equal(shouldAutoLock(1e9, 15, phase), false, phase);
    });
});

describe("Locking on screen lock and standby", () => {
    it("locks on screen lock, standby and shutdown when the setting is on", () => {
        for (const event of ["lock-screen", "suspend", "shutdown"] as const)
            assert.equal(shouldLockOnPowerEvent(event, true, "unlocked"), true, event);
    });

    it("does nothing on the poll timeout, on unlocking, with the setting off, or when not unlocked", () => {
        assert.equal(shouldLockOnPowerEvent("timeout", true, "unlocked"), false);
        assert.equal(shouldLockOnPowerEvent("unlock-screen", true, "unlocked"), false);
        assert.equal(shouldLockOnPowerEvent("lock-screen", false, "unlocked"), false);
        assert.equal(shouldLockOnPowerEvent("lock-screen", true, "locked"), false);
    });
});

describe("Unlocking with the screen (\"Unlock with Windows\")", () => {
    it("unlocks again only after its own screen lock, and only with Windows unlock on", () => {
        assert.equal(shouldUnlockOnPowerEvent("unlock-screen", true, true, "locked"), true);
        assert.equal(shouldUnlockOnPowerEvent("unlock-screen", false, true, "locked"), false, "locked by hand or after inactivity");
        assert.equal(shouldUnlockOnPowerEvent("unlock-screen", true, false, "locked"), false, "password mode");
        assert.equal(shouldUnlockOnPowerEvent("unlock-screen", true, true, "unlocked"), false);
        assert.equal(shouldUnlockOnPowerEvent("lock-screen", true, true, "locked"), false);
        assert.equal(shouldUnlockOnPowerEvent("timeout", true, true, "locked"), false);
    });
});
