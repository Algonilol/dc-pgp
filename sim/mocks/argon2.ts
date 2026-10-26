/*
 * DcPgp simulation – discord/argon2.ts without the Web Worker: the same Argon2id from hash-wasm, called directly.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { argon2id } from "hash-wasm";

import type { Argon2Fn } from "../../core/kdf";

export const argon2: Argon2Fn = async (password, salt, p) =>
    argon2id({ password, salt, parallelism: p.p, iterations: p.t, memorySize: p.m, hashLength: 32, outputType: "binary" });
