/*
 * DcPgp – lock icon (Material Design icons "lock" / "lock_open", Apache-2.0)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { LockIcon as LockState } from "../core/menus";

const CLOSED = "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z";
const OPEN = "M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6h1.9c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm0 12H6V10h12v10z";

const COLORS: Record<LockState, string> = {
    on: "var(--status-positive, #23a55a)",
    off: "currentColor",
    unavailable: "var(--interactive-muted, #4e5058)",
    warning: "var(--status-danger, #f23f43)"
};

/** `closed` overrides the shape, e.g. a grey closed lock for "encrypted, but not verified". */
export function LockIcon({ state = "off", closed, width = 20, height = 20, className }: { state?: LockState; closed?: boolean; width?: number | string; height?: number | string; className?: string; }) {
    const isClosed = closed ?? (state === "on" || state === "warning");
    return (
        <svg width={width} height={height} viewBox="0 0 24 24" className={className} style={{ color: COLORS[state] }} aria-hidden="true">
            <path fill="currentColor" d={isClosed ? CLOSED : OPEN} />
        </svg>
    );
}
