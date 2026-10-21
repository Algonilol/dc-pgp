/*
 * DcPgp – copying to the clipboard with automatic clearing (setting "clipboardClearSeconds").
 * The copied text is never logged; the clipboard is only cleared if it still holds exactly this text.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { copyToClipboard } from "@utils/clipboard";

import { clipboardClearDelayMs } from "../core/clipboard";
import { settings } from "../settings";
import { Native } from "./native";
import { logger } from "./state";

export async function copyAndMaybeClear(text: string): Promise<void> {
    try {
        await navigator.clipboard.writeText(text);
    } catch {
        // Discord's desktop app may refuse the web clipboard permission; Vencord's helper goes through Discord itself.
        await copyToClipboard(text);
    }
    const delay = clipboardClearDelayMs(settings.store.clipboardClearSeconds);
    if (delay == null) return;
    setTimeout(() => {
        Native.clearClipboardIfEquals(text).catch(() => logger.warn("Could not clear the clipboard"));
    }, delay);
}
