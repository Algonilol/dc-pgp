/*
 * DcPgp – when to lock automatically: after inactivity, and when Windows locks or goes to sleep
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { MenuPhase } from "./menus";

export function shouldAutoLock(idleSeconds: number, autoLockMinutes: number, phase: MenuPhase): boolean {
    if (phase !== "unlocked") return false;
    if (!Number.isFinite(autoLockMinutes) || autoLockMinutes <= 0) return false;
    if (!Number.isFinite(idleSeconds)) return false;
    return idleSeconds >= autoLockMinutes * 60;
}

/** What the native long poll reports; "timeout" only means "ask again". */
export type PowerEvent = "lock-screen" | "unlock-screen" | "suspend" | "shutdown" | "timeout";

export function shouldLockOnPowerEvent(event: PowerEvent, lockOnScreenLock: boolean, phase: MenuPhase): boolean {
    return event !== "timeout" && event !== "unlock-screen" && lockOnScreenLock && phase === "unlocked";
}

/**
 * With "Unlock with Windows", DcPgp follows Windows: locked with the screen, unlocked again with it.
 * Only if it was this lock: a lock by hand or after inactivity stays until the user unlocks.
 */
export function shouldUnlockOnPowerEvent(event: PowerEvent, lockedWithScreen: boolean, windowsUnlock: boolean, phase: MenuPhase): boolean {
    return event === "unlock-screen" && lockedWithScreen && windowsUnlock && phase === "locked";
}
