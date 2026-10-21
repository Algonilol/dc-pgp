/*
 * DcPgp – byte helpers: encodings and random numbers
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text: string): Uint8Array {
    return encoder.encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
    return strictDecoder.decode(bytes);
}

export function utf8Length(text: string): number {
    return encoder.encode(text).length;
}

export function toBase64(bytes: Uint8Array): string {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk)
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    return btoa(binary);
}

export function fromBase64(b64: string): Uint8Array {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

export function toHex(bytes: Uint8Array): string {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
}

export function fromHex(hex: string): Uint8Array {
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex string");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

export function randomBytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    crypto.getRandomValues(out);
    return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
    }
    return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

/** Uniform random integer in [0, max) using rejection sampling. */
export function randomInt(max: number): number {
    if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) throw new Error("randomInt: invalid range");
    const limit = Math.floor(2 ** 32 / max) * max;
    const buf = new Uint32Array(1);
    for (;;) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) return buf[0] % max;
    }
}

const URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function randomUrlSafe(length: number): string {
    let s = "";
    for (let i = 0; i < length; i++) s += URL_SAFE[randomInt(URL_SAFE.length)];
    return s;
}

/** Copies into a fresh ArrayBuffer-backed array (WebCrypto rejects views on shared or offset buffers in some engines). */
export function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    return new Uint8Array(bytes) as Uint8Array<ArrayBuffer>;
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
    const bytes = typeof data === "string" ? utf8(data) : data;
    return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(bytes))));
}
