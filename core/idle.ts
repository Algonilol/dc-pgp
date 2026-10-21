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
export type PowerEvent = "lock-screen" | "suspend" | "shutdown" | "timeout";

export function shouldLockOnPowerEvent(event: PowerEvent, lockOnScreenLock: boolean, phase: MenuPhase): boolean {
    return event !== "timeout" && lockOnScreenLock && phase === "unlocked";
}
