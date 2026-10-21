/*
 * DcPgp – password strength: zxcvbn for pattern detection, our own conservative bit count for the decision
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { MatchEstimated, ZxcvbnFactory, ZxcvbnResult } from "@zxcvbn-ts/core";

/** 4 truly random words from the ~7776-word list (4 × 12.9 bits). */
export const MIN_BITS = 51.5;
export const MIN_LENGTH = 12;
/** zxcvbn's own brute-force cardinality: 10 guesses per character. */
const BRUTEFORCE_BITS_PER_CHAR = Math.log2(10);
const DICEWARE_DICTIONARY = "diceware";

export interface StrengthResult {
    ok: boolean;
    /** Our conservative estimate in bits; this decides acceptance. */
    bits: number;
    crackTime: string;
    warning: string | null;
    suggestions: string[];
}

let factory: Promise<ZxcvbnFactory> | null = null;
let dicewareBits = Math.log2(7776);

/** Dictionaries are large, so they are only loaded when a password is actually checked. */
function getFactory(diceware: string[]): Promise<ZxcvbnFactory> {
    factory ??= (async () => {
        const [core, common, de, en] = await Promise.all([
            import("@zxcvbn-ts/core"),
            import("@zxcvbn-ts/language-common"),
            import("@zxcvbn-ts/language-de"),
            import("@zxcvbn-ts/language-en")
        ]);
        dicewareBits = Math.log2(diceware.length);
        // zxcvbn-ts ships the EFF list as "diceware-common" and treats its alphabetical order as frequency
        // ("abacus" = most common word). Our own copy is credited flat instead, see conservativeBits.
        const { "diceware-common": _alphabetical, ...commonDictionary } = common.dictionary as Record<string, unknown>;
        // German dictionaries stay: common German words in passwords must be recognised as weak.
        return new core.ZxcvbnFactory({
            translations: en.translations,
            graphs: common.adjacencyGraphs,
            dictionary: { ...commonDictionary, ...en.dictionary, ...de.dictionary, [DICEWARE_DICTIONARY]: diceware } as any,
            // Fuzzy matching maps real words to unrelated short entries ("baffle" → a zodiac sign, ~3 bits).
            useLevenshteinDistance: false
        });
    })();
    return factory;
}

/**
 * zxcvbn multiplies per-segment guesses with an ordering factorial and minimum floors and
 * credits unknown words like random characters, which badly overrates word combinations.
 * We add up each recognised segment on its own: a word of our public list counts 12.9 bits
 * (attackers know the list), other dictionary words by their frequency rank, unknown
 * characters at log2(10) bits each, separators not at all.
 */
export function conservativeBits(result: Pick<ZxcvbnResult, "sequence">): number {
    let bits = 0;
    for (const m of result.sequence as MatchEstimated[]) {
        if (m.pattern === "separator") continue;
        if (m.pattern === "bruteforce") bits += BRUTEFORCE_BITS_PER_CHAR * m.token.length;
        else if (m.pattern === "dictionary" && m.dictionaryName === DICEWARE_DICTIONARY) bits += dicewareBits;
        else bits += Math.log2(Math.max(2, Number(m.guesses) || 2));
    }
    return bits;
}

/** Words joined by simple separators, e.g. "sun-moon-stars-sky" or "word word word". */
const SEPARATED_WORDS = /^[\p{L}\p{N}]+(?:[-_. ][\p{L}\p{N}]+)+$/u;

export async function checkStrength(password: string, diceware: string[], userInputs: string[] = [], generated?: string | null): Promise<StrengthResult> {
    const z = await getFactory(diceware);
    const r = await z.checkAsync(password, userInputs);
    let bits = conservativeBits(r);
    if (SEPARATED_WORDS.test(password)) {
        // zxcvbn sometimes glues words and separators into one brute-force span ("sun-moon-" ≈ 30 bits),
        // so each word is also scored on its own and the lower total counts.
        let perWord = 0;
        for (const word of password.split(/[-_. ]/)) perWord += conservativeBits(await z.checkAsync(word, userInputs));
        bits = Math.min(bits, perWord);
    }
    const isGenerated = generated != null && password === generated;
    const ok = isGenerated || (password.length >= MIN_LENGTH && bits >= MIN_BITS);
    return {
        ok,
        bits,
        crackTime: r.crackTimes.offlineSlowHashingXPerSecond.display,
        warning: r.feedback.warning,
        suggestions: r.feedback.suggestions
    };
}
