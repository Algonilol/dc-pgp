/*
 * DcPgp – test helpers (Node only)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { hkdfSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { argon2id } from "hash-wasm";

import type { Argon2Fn, Argon2Params } from "../core/kdf";
import { readPrivateKey, unlockPrivateKey } from "../core/pgp";
import type { DeviceMixer } from "../core/vault";

export const FIXTURES = join(import.meta.dirname, "fixtures");
export const fixture = (name: string) => readFileSync(join(FIXTURES, name), "utf8");
export const GPG_PASSPHRASE = fixture("gpg-passphrase.txt").trim();

export const argon2: Argon2Fn = async (password, salt, p) =>
    argon2id({ password, salt, parallelism: p.p, iterations: p.t, memorySize: p.m, hashLength: 32, outputType: "binary" });

export const FAST_PARAMS: Argon2Params = { m: 8 * 1024, t: 1, p: 1 };

export function makeMixer(deviceKey = randomBytes(32)): DeviceMixer {
    return async (argonOut, salt) => new Uint8Array(hkdfSync("sha256", Buffer.concat([argonOut, deviceKey]), salt, "dcpgp vault slotA v1", 32));
}

export async function gpgKey(name: "alice" | "bob" | "rsa") {
    const key = await readPrivateKey(fixture(`gpg-${name}.sec.asc`));
    return unlockPrivateKey(key, GPG_PASSPHRASE);
}

export const IDS = {
    alice: "111111111111111111",
    bob: "222222222222222222",
    carol: "333333333333333333",
    dm: "444444444444444444",
    other: "555555555555555555"
};
