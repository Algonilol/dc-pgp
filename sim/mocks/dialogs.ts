/*
 * DcPgp simulation – the plugin's ui/dialogs.tsx: dialogs are answered from sim/world.ts's answers (by a part
 * of the title), otherwise cancelled; toasts are recorded.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { answers, dialogs, toasts } from "../world";

export interface ChoiceOption<T> {
    label: string;
    value: T;
    variant?: string;
}

export function choose<T>(title: string, _body: unknown, options: ChoiceOption<T>[], cancelValue: T): Promise<T> {
    const scripted = [...answers.entries()].find(([part]) => title.includes(part))?.[1];
    const picked = scripted !== undefined ? options.find(o => o.label === scripted) : undefined;
    dialogs.push({ title, answer: picked?.label ?? "(closed)" });
    return Promise.resolve(picked ? picked.value : cancelValue);
}

export function confirmDialog(title: string, body: unknown, confirmText: string, cancelText = "Cancel", _danger = false): Promise<boolean> {
    return choose(title, body, [{ label: cancelText, value: false }, { label: confirmText, value: true }], false);
}

export function alertDialog(title: string, _body: unknown, _buttonText = "Got it"): Promise<void> {
    dialogs.push({ title, answer: "(ok)" });
    return Promise.resolve();
}

export const toastError = (text: string) => void toasts.push({ kind: "error", text });
export const toastSuccess = (text: string) => void toasts.push({ kind: "success", text });
export const toastInfo = (text: string) => void toasts.push({ kind: "info", text });
