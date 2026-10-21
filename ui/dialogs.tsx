/*
 * DcPgp – promise-based dialogs on top of Discord's modal component
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Paragraph } from "@components/Paragraph";
import type { ModalActionVariant } from "@vencord/discord-types";
import { Modal, openModal, showToast } from "@webpack/common";
import type { ReactNode } from "react";

export interface ChoiceOption<T> {
    label: string;
    value: T;
    variant?: ModalActionVariant;
}

/** Shows a modal with one button per option and resolves with the chosen value (cancelValue if dismissed). */
export function choose<T>(title: string, body: ReactNode, options: ChoiceOption<T>[], cancelValue: T): Promise<T> {
    return new Promise<T>(resolve => {
        let settled = false;
        const finish = (value: T) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };
        openModal(props => (
            <Modal
                {...props}
                title={title}
                actions={options.map(o => ({
                    text: o.label,
                    variant: o.variant ?? "secondary",
                    onClick: () => {
                        finish(o.value);
                        props.onClose();
                    }
                }))}
            >
                <div className="dcpgp-dialog-body">
                    {typeof body === "string" ? <Paragraph>{body}</Paragraph> : body}
                </div>
            </Modal>
        ), { onCloseCallback: () => finish(cancelValue) });
    });
}

export function confirmDialog(title: string, body: ReactNode, confirmText: string, cancelText = "Cancel", danger = false): Promise<boolean> {
    return choose(title, body, [
        { label: cancelText, value: false },
        { label: confirmText, value: true, variant: danger ? "critical-primary" : "primary" }
    ], false);
}

export function alertDialog(title: string, body: ReactNode, buttonText = "Got it"): Promise<void> {
    return choose(title, body, [{ label: buttonText, value: undefined, variant: "primary" }], undefined);
}

export function toastError(text: string) {
    showToast({ text, variant: "critical" });
}

export function toastSuccess(text: string) {
    showToast({ text, variant: "success" });
}

export function toastInfo(text: string) {
    showToast({ text, variant: "default" });
}
