/*
 * DcPgp – diceware passphrases
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { randomInt } from "./bytes";

export const GENERATED_WORDS = 5;

export function parseWordlist(text: string): string[] {
    const words = text.split(/\r?\n/).map(w => w.trim()).filter(Boolean);
    if (words.length < 1024 || new Set(words).size !== words.length) throw new Error("Invalid wordlist");
    return words;
}

/** Diceware-style passphrase: uniformly random words joined by dashes. */
export function generatePassphrase(words: string[], count = GENERATED_WORDS): string {
    return Array.from({ length: count }, () => words[randomInt(words.length)]).join("-");
}

export function passphraseEntropyBits(words: string[], count = GENERATED_WORDS): number {
    return count * Math.log2(words.length);
}
