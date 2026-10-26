/*
 * DcPgp simulation – the globals the plugin finds in Discord's renderer: VencordNative (here: the simulated
 * native part), Vencord's JSX factory, and the little of the DOM that the CSS hiding touches.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { nativeMock } from "./world";

const g = globalThis as any;

g.VencordNative = { pluginHelpers: { DcPgp: nativeMock } };
g.VencordCreateElement = (type: unknown, props: unknown, ...children: unknown[]) => ({ type, props, children });
g.VencordFragment = Symbol("VencordFragment");
g.requestAnimationFrame ??= (cb: (t: number) => void) => setTimeout(() => cb(Date.now()), 0);

/** The style element DcPgp writes its hiding rules into, readable by the run. */
export const styleSheet = {
    textContent: "",
    isConnected: false,
    id: "",
    remove() {
        this.isConnected = false;
    }
};
g.document ??= {
    createElement: () => styleSheet,
    head: { appendChild: (el: { isConnected: boolean; }) => { el.isConnected = true; } }
};
