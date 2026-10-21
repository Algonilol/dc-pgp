/*
 * DcPgp – renderer access to the native (main process) helpers
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { PluginNative } from "@utils/types";

import type { DeviceMixer } from "../core/vault";

export const Native = VencordNative.pluginHelpers.DcPgp as PluginNative<typeof import("../native")>;

export const nativeMixer: DeviceMixer = async (argonOutput, salt) => {
    const out = await Native.deriveSlotKey(argonOutput, salt);
    return new Uint8Array(out);
};

export type DeviceStatus = "ok" | "missing" | "unreadable" | "unavailable";

export async function deviceStatus(): Promise<DeviceStatus> {
    try {
        return await Native.deviceKeyStatus() as DeviceStatus;
    } catch {
        return "unavailable";
    }
}
