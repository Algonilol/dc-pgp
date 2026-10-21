/*
 * DcPgp – native part (Electron main process). Keep this small: every export is callable from the renderer.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { DATA_DIR } from "@main/utils/constants";
import { createHash, hkdfSync, randomBytes } from "crypto";
import { app, clipboard, dialog, IpcMainInvokeEvent, powerMonitor, safeStorage } from "electron";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { writeFile } from "fs/promises";
import { join } from "path";

import { sameClipboardText } from "./core/clipboard";

const DIR = join(DATA_DIR, "dcpgp");
const DEVICE_KEY_FILE = join(DIR, "device.key");

type DeviceKeyStatus = "ok" | "missing" | "unreadable" | "unavailable";

let deviceKey: Buffer | null = null;

function encryptionAvailable(): boolean {
    try {
        return app.isReady() && safeStorage.isEncryptionAvailable();
    } catch {
        return false;
    }
}

function readDeviceKey(): Buffer | null {
    if (deviceKey) return deviceKey;
    if (!existsSync(DEVICE_KEY_FILE)) return null;
    const decoded = Buffer.from(safeStorage.decryptString(readFileSync(DEVICE_KEY_FILE)), "base64");
    if (decoded.length !== 32) throw new Error("device key has wrong length");
    deviceKey = decoded;
    return deviceKey;
}

/** Never overwrites an existing (possibly unreadable) key file: that would lock the vault forever. */
function getOrCreateDeviceKey(): Buffer {
    if (!encryptionAvailable()) throw new Error("DCPGP_DEVICE_UNAVAILABLE");
    const existing = readDeviceKey();
    if (existing) return existing;
    if (existsSync(DEVICE_KEY_FILE)) throw new Error("DCPGP_DEVICE_UNREADABLE");
    mkdirSync(DIR, { recursive: true });
    const fresh = randomBytes(32);
    const tmp = DEVICE_KEY_FILE + ".tmp";
    writeFileSync(tmp, safeStorage.encryptString(fresh.toString("base64")), { mode: 0o600 });
    renameSync(tmp, DEVICE_KEY_FILE);
    deviceKey = fresh;
    return fresh;
}

export function deviceKeyStatus(_: IpcMainInvokeEvent): DeviceKeyStatus {
    if (!encryptionAvailable()) return "unavailable";
    if (!existsSync(DEVICE_KEY_FILE)) return "missing";
    try {
        return readDeviceKey() ? "ok" : "missing";
    } catch {
        return "unreadable";
    }
}

/** KEK = HKDF(argon2 output ‖ device key). The device key itself never leaves this process. */
export function deriveSlotKey(_: IpcMainInvokeEvent, argonOutput: Uint8Array, salt: Uint8Array): Uint8Array {
    if (!(argonOutput instanceof Uint8Array) || argonOutput.length !== 32 || !(salt instanceof Uint8Array) || salt.length < 16)
        throw new Error("invalid input");
    const key = getOrCreateDeviceKey();
    const ikm = Buffer.concat([Buffer.from(argonOutput), key]);
    const out = new Uint8Array(hkdfSync("sha256", ikm, Buffer.from(salt), "dcpgp vault slotA v1", 32));
    ikm.fill(0);
    return out;
}

/** Key for hashing the ids of encrypted chats, so the mod can recognise them while locked. */
export function guardKey(_: IpcMainInvokeEvent): Uint8Array {
    const key = getOrCreateDeviceKey();
    return new Uint8Array(hkdfSync("sha256", key, Buffer.from("dcpgp"), "dcpgp guard v1", 32));
}

export function getIdleSeconds(_: IpcMainInvokeEvent): number {
    try {
        return powerMonitor.getSystemIdleTime();
    } catch {
        return 0;
    }
}

export function getIdleState(_: IpcMainInvokeEvent, thresholdSeconds: number): string {
    try {
        return powerMonitor.getSystemIdleState(Math.max(1, Math.floor(thresholdSeconds)));
    } catch {
        return "unknown";
    }
}

type PowerEvent = "lock-screen" | "suspend" | "shutdown" | "timeout";
let waiters: Array<(e: PowerEvent) => void> = [];
let subscribed = false;

function subscribePower() {
    if (subscribed) return;
    subscribed = true;
    for (const ev of ["lock-screen", "suspend", "shutdown"] as const) {
        powerMonitor.on(ev as any, () => {
            const current = waiters;
            waiters = [];
            for (const resolve of current) resolve(ev);
        });
    }
}

/** Long poll: resolves on screen lock, standby or shutdown, or after the timeout. */
export function waitForPowerEvent(_: IpcMainInvokeEvent, timeoutMs: number): Promise<PowerEvent> {
    subscribePower();
    return new Promise(resolve => {
        const done = (ev: PowerEvent) => {
            clearTimeout(timer);
            resolve(ev);
        };
        const timer = setTimeout(() => {
            waiters = waiters.filter(w => w !== done);
            resolve("timeout");
        }, Math.min(Math.max(1000, timeoutMs | 0), 15 * 60 * 1000));
        waiters.push(done);
    });
}

/** Clears the clipboard only if it still holds the text we were told about (compared by hash). */
export function clearClipboardIfMatches(_: IpcMainInvokeEvent, sha256Hex: string): boolean {
    try {
        const current = clipboard.readText();
        if (!current) return false;
        const hash = createHash("sha256").update(current, "utf8").digest("hex");
        if (hash !== sha256Hex) return false;
        clipboard.clear();
        return true;
    } catch {
        return false;
    }
}

/**
 * Clears the clipboard only if it still holds exactly this text. Unlike the hash check above, the
 * line-ending style may differ: Windows stores text copied with the web clipboard API as CRLF.
 */
export function clearClipboardIfEquals(_: IpcMainInvokeEvent, fullText: string): boolean {
    try {
        if (typeof fullText !== "string") return false;
        const current = clipboard.readText();
        if (!current || !sameClipboardText(current, fullText)) return false;
        clipboard.clear();
        return true;
    } catch {
        return false;
    }
}

/** Shows a native save dialog and writes the text. Returns the chosen path or null if cancelled. */
export async function saveTextFile(_: IpcMainInvokeEvent, defaultName: string, content: string, extension: "asc" | "dcpgp" = "asc"): Promise<string | null> {
    const safeName = String(defaultName).replace(/[\\/:*?"<>|]/g, "_").slice(0, 120) || "dcpgp.asc";
    const filter = extension === "dcpgp"
        ? { name: "DcPgp backup", extensions: ["dcpgp"] }
        : { name: "OpenPGP", extensions: ["asc"] };
    const result = await dialog.showSaveDialog({
        title: "DcPgp – Save file",
        defaultPath: join(app.getPath("documents"), safeName),
        filters: [filter, { name: "All files", extensions: ["*"] }]
    });
    if (result.canceled || !result.filePath) return null;
    await writeFile(result.filePath, String(content), { encoding: "utf8", mode: 0o600 });
    return result.filePath;
}
