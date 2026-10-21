/*
 * DcPgp – clipboard decisions shared by the renderer and the native part
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Whether the clipboard still holds the text we copied. The whole text is compared; only the
 * line-ending style may differ, because Windows stores text from the web clipboard API with CRLF.
 */
export function sameClipboardText(current: string, copied: string): boolean {
    const normalize = (s: string) => s.replace(/\r\n?/g, "\n");
    return copied.length > 0 && normalize(current) === normalize(copied);
}

/** Milliseconds until the clipboard is cleared, or null when clearing is off. */
export function clipboardClearDelayMs(seconds: number): number | null {
    return Number.isFinite(seconds) && seconds > 0 ? Math.round(seconds * 1000) : null;
}
