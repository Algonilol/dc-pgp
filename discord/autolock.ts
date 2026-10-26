/*
 * DcPgp – automatic locking after inactivity and on screen lock / standby
 * (settings "autoLockMinutes" and "lockOnScreenLock"). Decisions: core/idle.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { shouldAutoLock, shouldLockOnPowerEvent, shouldUnlockOnPowerEvent } from "../core/idle";
import { settings } from "../settings";
import { lockVault, unlockWithWindows } from "./actions";
import { Native } from "./native";
import { logger, S } from "./state";

const CHECK_EVERY_MS = 30_000;
/** The native long poll returns at the latest after this, so a stopped loop ends soon. */
const POWER_WAIT_MS = 15 * 60_000;
const POWER_RETRY_MS = 60_000;

let timer: ReturnType<typeof setInterval> | null = null;
/** Changes on every stop: an old power loop sees that and ends instead of re-arming. */
let generation = 0;
/** The current lock came from Windows locking: with "Unlock with Windows", Windows unlocking ends it. */
let lockedWithScreen = false;
const warned = new Set<string>();

function warnOnce(what: string, e: unknown) {
    if (warned.has(what)) return;
    warned.add(what);
    logger.warn(`Auto-lock: ${what} not available`, (e as Error)?.message ?? e);
}

async function checkIdle() {
    if (S.phase !== "unlocked") return;
    const minutes = settings.store.autoLockMinutes;
    if (!(minutes > 0)) return;
    try {
        const idle = await Native.getIdleSeconds();
        if (shouldAutoLock(idle, minutes, S.phase)) lockVault("idle");
    } catch (e) {
        warnOnce("idle time", e);
    }
}

async function watchPower(gen: number) {
    while (gen === generation) {
        try {
            const event = await Native.waitForPowerEvent(POWER_WAIT_MS);
            if (gen !== generation) return;
            if (S.phase === "unlocked") lockedWithScreen = false;
            if (shouldLockOnPowerEvent(event, settings.store.lockOnScreenLock, S.phase)) {
                lockVault("power");
                lockedWithScreen = true;
            } else if (shouldUnlockOnPowerEvent(event, lockedWithScreen, !!S.file?.w, S.phase)) {
                lockedWithScreen = false;
                unlockWithWindows().catch(e => logger.warn("Unlocking with Windows after the screen lock failed", e));
            }
        } catch (e) {
            warnOnce("power events", e);
            await new Promise(resolve => setTimeout(resolve, POWER_RETRY_MS));
        }
    }
}

export function startAutolock() {
    if (timer) return;
    timer = setInterval(() => void checkIdle(), CHECK_EVERY_MS);
    void watchPower(generation);
}

export function stopAutolock() {
    if (timer) clearInterval(timer);
    timer = null;
    generation++;
}
