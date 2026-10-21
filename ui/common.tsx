/*
 * DcPgp – small shared UI helpers
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Paragraph } from "@components/Paragraph";
import type { ReactNode } from "react";

export const COLORS = {
    ok: "var(--text-positive, #23a55a)",
    warn: "var(--text-warning, #f0b232)",
    bad: "var(--text-danger, #f23f43)"
};

export const mono = { fontFamily: "var(--font-code, monospace)", userSelect: "text" as const };

export const errorText = (e: unknown) => e instanceof Error ? e.message : String(e);

/** Button labels don't wrap: a long file name would push the dialog sideways. */
export const shortName = (name: string, max = 40) => name.length > max ? "…" + name.slice(-(max - 1)) : name;

export function ErrorText({ children }: { children: ReactNode; }) {
    return <Paragraph style={{ color: COLORS.bad, marginTop: 8 }}>{children}</Paragraph>;
}

export function Gap({ size = 12 }: { size?: number; }) {
    return <div style={{ height: size }} />;
}
