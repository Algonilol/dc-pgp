/*
 * DcPgp – password stretching (Argon2id) and its calibration
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { utf8 } from "./bytes";

/** m is the memory cost in KiB, t the number of passes, p the parallelism. */
export interface Argon2Params {
    m: number;
    t: number;
    p: number;
}

export type Argon2Fn = (password: Uint8Array, salt: Uint8Array, params: Argon2Params) => Promise<Uint8Array>;

export const DEFAULT_MEMORY_KIB = 256 * 1024;
export const MIN_ITERATIONS = 3;
export const MAX_ITERATIONS = 10;

export function passwordBytes(password: string): Uint8Array {
    return utf8(password.normalize("NFC"));
}

export function validateArgon2Params(params: Argon2Params): void {
    const { m, t, p } = params;
    const ok = Number.isInteger(m) && Number.isInteger(t) && Number.isInteger(p)
        && m >= 8 * 1024 && m <= 1024 * 1024
        && t >= 1 && t <= 50
        && p >= 1 && p <= 8;
    if (!ok) throw new Error("Vault damaged: invalid Argon2 parameters");
}

/**
 * Picks the number of passes so one derivation takes roughly targetMs on this machine.
 * Memory stays fixed; only the pass count adapts.
 */
export async function calibrateArgon2(argon2: Argon2Fn, targetMs = 1000, memoryKiB = DEFAULT_MEMORY_KIB): Promise<Argon2Params> {
    const probe: Argon2Params = { m: memoryKiB, t: 1, p: 1 };
    const salt = new Uint8Array(16);
    const start = performance.now();
    await argon2(utf8("calibration"), salt, probe);
    const perPass = Math.max(1, performance.now() - start);
    const t = Math.min(MAX_ITERATIONS, Math.max(MIN_ITERATIONS, Math.round(targetMs / perPass)));
    return { m: memoryKiB, t, p: 1 };
}
