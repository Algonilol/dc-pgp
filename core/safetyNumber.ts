/*
 * DcPgp – safety numbers: one number both sides compare to verify each other's keys
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { sha512 } from "@noble/hashes/sha2.js";

import { concatBytes, fromHex, utf8 } from "./bytes";

const ITERATIONS = 5200;
const VERSION = new Uint8Array([0, 1]);

/** 30 digits that identify one party (key fingerprint bound to a Discord user id). */
function partyDigits(fingerprintHex: string, userId: string): string {
    const fpr = fromHex(fingerprintHex);
    let hash = sha512(concatBytes(VERSION, fpr, utf8(userId)));
    for (let i = 0; i < ITERATIONS; i++) hash = sha512(concatBytes(hash, fpr));
    let digits = "";
    for (let chunk = 0; chunk < 6; chunk++) {
        let value = 0;
        for (let b = 0; b < 5; b++) value = value * 256 + hash[chunk * 5 + b];
        digits += String(value % 100000).padStart(5, "0");
    }
    return digits;
}

/** 60 digits, identical on both sides, shown as 12 groups of 5. */
export function safetyNumber(a: { fpr: string; userId: string; }, b: { fpr: string; userId: string; }): string {
    const parts = [partyDigits(a.fpr, a.userId), partyDigits(b.fpr, b.userId)].sort();
    return parts.join("");
}

export function formatSafetyNumber(number: string): string[] {
    return number.match(/.{5}/g) ?? [];
}
