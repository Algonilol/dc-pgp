/*
 * DcPgp – raw ciphertext: the toolbar under a block that Discord shows itself (copy, unlock, view),
 * and the "View Raw PGP" dialog that shows the exact PGP block. Knows only the raw text and
 * optional actions, so other modes can reuse it.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, TextButton } from "@components/Button";
import { Paragraph } from "@components/Paragraph";
import type { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal } from "@webpack/common";

import { copyAndMaybeClear } from "../discord/clipboard";
import { Gap, mono } from "./common";
import { toastError, toastSuccess } from "./dialogs";
import { LockIcon } from "./icons";

export interface RawCiphertextViewProps {
    /** Copied exactly as given: no trimming, no reformatting, never logged. */
    raw: string;
    label?: string;
    /** Without it there is no "Unlock" button. */
    onUnlock?: () => void;
    /** Without it there is no "View Raw PGP" button. */
    onViewRaw?: () => void;
    /** Shows the text itself (in the dialog); under a chat message Discord already shows it. */
    showText?: boolean;
    copyLabel?: string;
}

export function RawCiphertextView({ raw, label, onUnlock, onViewRaw, showText, copyLabel = "Copy raw ciphertext" }: RawCiphertextViewProps) {
    async function copy() {
        try {
            await copyAndMaybeClear(raw);
            toastSuccess("Ciphertext copied.");
        } catch {
            toastError("Could not copy the ciphertext.");
        }
    }

    if (showText)
        return (
            <div>
                <pre style={{ ...mono, margin: 0, padding: 8, maxHeight: 320, overflowY: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, borderRadius: 4, background: "var(--background-secondary, rgba(127,127,127,.1))" }}>
                    {raw}
                </pre>
                <Gap size={8} />
                <Button size="small" variant="primary" onClick={() => void copy()}>{copyLabel}</Button>
            </div>
        );

    return (
        <div className="dcpgp-note">
            <LockIcon state="unavailable" closed width={14} height={14} />
            {label && <span>{label}</span>}
            {onUnlock && <TextButton variant="link" onClick={() => onUnlock()}>Unlock</TextButton>}
            {onViewRaw && <TextButton variant="link" onClick={() => onViewRaw()}>View Raw PGP</TextButton>}
            <TextButton variant="link" onClick={() => void copy()}>{copyLabel}</TextButton>
        </div>
    );
}

function RawCiphertextModal({ raw, ...props }: RenderModalProps & { raw: string; }) {
    return (
        <Modal {...props} title="Raw PGP message" actions={[{ text: "Close", variant: "secondary", onClick: () => props.onClose() }]}>
            <Paragraph>The encrypted block exactly as it was sent. You can also decrypt it with Kleopatra or GnuPG.</Paragraph>
            <Gap size={8} />
            <RawCiphertextView raw={raw} showText copyLabel="Copy Ciphertext" />
        </Modal>
    );
}

/** Opens the "View Raw PGP" dialog for an armored PGP block. */
export function openRawCiphertextModal(armored: string) {
    openModal(props => <RawCiphertextModal {...props} raw={armored} />);
}
