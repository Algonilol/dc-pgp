/*
 * DcPgp simulation – Vencord's "@api/MessageEvents", with the same semantics as the real one: listeners run
 * in order, a listener's error is logged and ignored (the message goes out anyway), { cancel: true } stops it.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { logLines } from "../world";

type Listener = (...args: any[]) => any;

const sendListeners = new Set<Listener>();
const editListeners = new Set<Listener>();

async function run(listeners: Set<Listener>, args: unknown[]): Promise<boolean> {
    for (const listener of listeners) {
        try {
            const result = await listener(...args);
            if (result?.cancel) return true;
        } catch (e) {
            logLines.push(`MessageEvents: listener error (ignored, like Vencord): ${(e as Error)?.message ?? e}`);
        }
    }
    return false;
}

export const _handlePreSend = (channelId: string, message: unknown, options: unknown, props: unknown) => run(sendListeners, [channelId, message, options, props]);
export const _handlePreEdit = (channelId: string, messageId: string, message: unknown) => run(editListeners, [channelId, messageId, message]);

export function addMessagePreSendListener(listener: Listener) {
    sendListeners.add(listener);
    return listener;
}

export function addMessagePreEditListener(listener: Listener) {
    editListeners.add(listener);
    return listener;
}

export const removeMessagePreSendListener = (listener: Listener) => sendListeners.delete(listener);
export const removeMessagePreEditListener = (listener: Listener) => editListeners.delete(listener);
