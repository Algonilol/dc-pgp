/*
 * DcPgp – Argon2id in a short-lived Web Worker, so Discord does not freeze and the
 * 256 MiB of working memory is released right after each derivation.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Logger } from "@utils/Logger";
import hashWasmArgon2Source from "file://../node_modules/hash-wasm/dist/argon2.umd.min.js";

import type { Argon2Fn, Argon2Params } from "../core/kdf";

const logger = new Logger("DcPgp");

const WORKER_GLUE = `
self.onmessage = async (e) => {
    const { password, salt, m, t, p } = e.data;
    try {
        const out = await self.hashwasm.argon2id({ password, salt, parallelism: p, iterations: t, memorySize: m, hashLength: 32, outputType: "binary" });
        self.postMessage({ ok: true, out }, [out.buffer]);
    } catch (err) {
        self.postMessage({ ok: false, error: String((err && err.message) || err) });
    }
};`;

class WorkerUnavailableError extends Error { }

let workerUrl: string | null = null;

function runInWorker(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        let worker: Worker;
        try {
            workerUrl ??= URL.createObjectURL(new Blob([hashWasmArgon2Source, "\n", WORKER_GLUE], { type: "text/javascript" }));
            worker = new Worker(workerUrl);
        } catch (e) {
            reject(new WorkerUnavailableError(String(e)));
            return;
        }
        const timeout = setTimeout(() => {
            worker.terminate();
            reject(new Error("Argon2: timeout"));
        }, 60_000);
        worker.onmessage = (e: MessageEvent) => {
            clearTimeout(timeout);
            worker.terminate();
            if (e.data?.ok) resolve(new Uint8Array(e.data.out));
            else reject(new Error("Argon2: " + e.data?.error));
        };
        worker.onerror = e => {
            clearTimeout(timeout);
            worker.terminate();
            reject(new WorkerUnavailableError(e.message || "Worker error"));
        };
        const pw = new Uint8Array(password);
        worker.postMessage({ password: pw, salt: new Uint8Array(salt), m: params.m, t: params.t, p: params.p }, [pw.buffer]);
    });
}

async function runInline(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
    const scope: Record<string, any> = {};

    const load = new Function("globalThis", "self", "define", "exports", "module", hashWasmArgon2Source + "\nreturn globalThis.hashwasm;");
    const hashwasm = load(scope, scope, undefined, undefined, undefined);
    return hashwasm.argon2id({ password, salt, parallelism: params.p, iterations: params.t, memorySize: params.m, hashLength: 32, outputType: "binary" });
}

export const argon2: Argon2Fn = async (password, salt, params) => {
    try {
        return await runInWorker(password, salt, params);
    } catch (e) {
        if (!(e instanceof WorkerUnavailableError)) throw e;
        logger.warn("Argon2 worker not available, computing on the main thread:", e.message);
        return runInline(password, salt, params);
    }
};
