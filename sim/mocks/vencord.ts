/*
 * DcPgp simulation – the rest of Vencord the plugin imports: plugin definition, settings, logger,
 * message accessories, chat bar buttons, components and small utils.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { DataStoreMock, logLines } from "../world";

export default function definePlugin<T>(plugin: T): T {
    return plugin;
}

export const OptionType = { STRING: 0, NUMBER: 1, BIGINT: 2, BOOLEAN: 3, SELECT: 4, SLIDER: 5, COMPONENT: 6, CUSTOM: 7 };

export function definePluginSettings(definition: Record<string, { default?: unknown; }>) {
    const store: Record<string, any> = {};
    for (const [key, def] of Object.entries(definition)) store[key] = def.default;
    return { store, def: definition, use: () => store, withPrivateSettings() { return this; } };
}

export class Logger {
    constructor(readonly name: string, readonly color?: string) { }
    private add(level: string, args: unknown[]) {
        logLines.push(`[${this.name}] ${level}: ${args.map(a => a instanceof Error ? a.message : typeof a === "string" ? a : JSON.stringify(a)).join(" ")}`);
    }
    log(...args: unknown[]) { this.add("log", args); }
    info(...args: unknown[]) { this.add("info", args); }
    debug(...args: unknown[]) { this.add("debug", args); }
    warn(...args: unknown[]) { this.add("warn", args); }
    error(...args: unknown[]) { this.add("error", args); }
}

export const plugins: Record<string, any> = {};

export const accessories = new Map<string, unknown>();
export const addMessageAccessory = (id: string, render: unknown) => void accessories.set(id, render);
export const removeMessageAccessory = (id: string) => void accessories.delete(id);

const Inert = () => null;
export const ChatBarButton = Inert;
export const Button = Inert;
export const TextButton = Inert;
export const Paragraph = Inert;

export const chooseFile = async () => null;
export const copyToClipboard = async (_text: string) => undefined;

export const { get, set, del, keys } = DataStoreMock;
