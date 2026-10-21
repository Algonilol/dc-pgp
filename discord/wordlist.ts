/*
 * DcPgp – passphrase wordlist: the EFF large wordlist (CC BY, Electronic Frontier Foundation), embedded at build time.
 * The four hyphenated words are left out, because generated passphrases use "-" as separator.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import wordlistText from "file://../core/wordlist-en.txt";

import { parseWordlist } from "../core/passphrase";

let words: string[] | null = null;

export function dicewareWords(): string[] {
    words ??= parseWordlist(wordlistText);
    return words;
}
