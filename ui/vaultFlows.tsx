/*
 * DcPgp – vault management flows: password, private key (show, remove, store), key file, vault backup
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button } from "@components/Button";
import { Paragraph } from "@components/Paragraph";
import { chooseFile } from "@utils/web";
import type { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, useEffect, useState } from "@webpack/common";

import { changePassword, changeSecurityMode, exportOwnKeyFile, exportVaultBackup, importVaultBackup, revealPrivateKey } from "../discord/actions";
import { copyAndMaybeClear } from "../discord/clipboard";
import { S, useDcPgpState } from "../discord/state";
import { settings } from "../settings";
import { COLORS, Gap, mono } from "./common";
import { choose, confirmDialog, toastError, toastSuccess } from "./dialogs";
import { openPasswordPrompt } from "./passwordFields";

export function openChangePasswordModal(title = "Change password", description?: string) {
    openPasswordPrompt({
        title,
        description: description ?? "The new password protects the vault on this PC (together with the device key).",
        confirmText: "Set password",
        kind: "new",
        async onSubmit(password, generated) {
            await changePassword(password, generated);
            toastSuccess("Password changed.");
        }
    });
}

/** Saves the own private key as a password-protected file; runs after() once saved. */
export function openKeyFileExport(after?: () => Promise<void>) {
    openPasswordPrompt({
        title: "Save key file",
        description: "The file contains your private key, protected with this password. You can import it into Kleopatra or unlock Discord-PGP with it. Keep it somewhere safe (e.g. a USB stick).",
        confirmText: "Save …",
        kind: "new",
        async onSubmit(password, generated) {
            const path = await exportOwnKeyFile(password, generated);
            if (!path) throw new Error("Saving was cancelled.");
            toastSuccess(`Key file saved: ${path}`);
            await after?.();
        }
    });
}

export async function openModeSwitch() {
    const session = S.session;
    if (!session) return toastError("Discord-PGP is locked.");

    if (session.file.mode === "stored") {
        const choice = await choose(
            "Remove the stored private key?",
            "Your private key will be removed from this PC (mode \"RAM only\"). Every time Discord starts, you then unlock with your key file and its passphrase. Without the key file you lose access to your encrypted messages.",
            [
                { label: "Cancel", value: "cancel" },
                { label: "Save key file & remove", value: "save", variant: "primary" },
                { label: "I have the key file", value: "have", variant: "critical-primary" }
            ],
            "cancel"
        );
        if (choice === "cancel") return;
        const switchToRam = async () => {
            await changeSecurityMode("ram", { keyFileConfirmed: true });
            toastSuccess("The private key is no longer stored on this PC. From now on, unlock with your key file.");
        };
        if (choice === "save") return openKeyFileExport(switchToRam);
        try {
            await switchToRam();
        } catch (e) {
            toastError(e instanceof Error ? e.message : String(e));
        }
        return;
    }

    openPasswordPrompt({
        title: "Store the private key on this PC",
        description: "Your private key is kept encrypted in the vault (mode \"Stored\"), protected by this password and this PC's device key. On startup, the password is then enough.",
        confirmText: "Store",
        kind: "new",
        async onSubmit(password, generated) {
            await changeSecurityMode("stored", { password, generated });
            toastSuccess("\"Stored\" mode is active.");
        }
    });
}

/** Shows the own private key, but only after the vault password was entered again. */
export function openShowPrivateKey() {
    openPasswordPrompt({
        title: "Show private key",
        description: "Enter your vault password to show your private key.",
        confirmText: "Show",
        kind: "existing",
        async onSubmit(password) {
            const armored = await revealPrivateKey(password);
            openModal(props => <PrivateKeyModal {...props} armored={armored} />);
        }
    });
}

function PrivateKeyModal({ armored, ...props }: RenderModalProps & { armored: string; }) {
    const s = useDcPgpState();
    const [revealed, setRevealed] = useState(false);
    // Locking (also automatically) closes it: the key must not stay on screen.
    useEffect(() => { if (!s.session) props.onClose(); }, [s.session]);

    async function copy() {
        try {
            await copyAndMaybeClear(armored);
            const seconds = settings.store.clipboardClearSeconds;
            toastSuccess(seconds > 0 ? `Private key copied – the clipboard is cleared in ${seconds} s.` : "Private key copied.");
        } catch {
            toastError("Could not copy the private key.");
        }
    }

    return (
        <Modal {...props} title="Your private key" actions={[{ text: "Close", variant: "secondary", onClick: () => props.onClose() }]}>
            <Paragraph style={{ color: COLORS.bad }}>
                Anyone who sees or copies this can read all your encrypted messages and sign in your name. Don't show it while sharing your screen. To move your key, prefer "Save key file" – that file is protected with a password.
            </Paragraph>
            <Gap size={8} />
            <pre
                aria-hidden={!revealed}
                style={{ ...mono, margin: 0, padding: 8, maxHeight: 280, overflowY: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, borderRadius: 4, background: "var(--background-secondary, rgba(127,127,127,.1))", filter: revealed ? "none" : "blur(6px)", userSelect: revealed ? "text" : "none" }}
            >
                {armored}
            </pre>
            <Gap size={8} />
            <div style={{ display: "flex", gap: 8 }}>
                <Button size="small" variant="secondary" onClick={() => setRevealed(!revealed)}>{revealed ? "Hide" : "Reveal"}</Button>
                <Button size="small" variant="secondary" onClick={() => void copy()}>Copy</Button>
            </div>
        </Modal>
    );
}

export function openBackupExport() {
    openPasswordPrompt({
        title: "Save vault backup",
        description: "The backup contains your contacts, chat settings and – in \"Stored\" mode – your private key. It is protected by this password only (no device key), so you can restore it on another PC.",
        confirmText: "Save …",
        kind: "new",
        async onSubmit(password, generated) {
            const path = await exportVaultBackup(password, generated);
            if (!path) throw new Error("Saving was cancelled.");
            toastSuccess(`Vault backup saved: ${path}`);
        }
    });
}

export async function startBackupImport() {
    if (S.file && !await confirmDialog(
        "Replace the vault?",
        "The vault on this PC will be replaced by the backup. The previous version is kept as a fallback copy.",
        "Choose backup …",
        "Cancel",
        true
    )) return;

    const file = await chooseFile(".dcpgp,application/json");
    if (!file) return;
    let text: string;
    try {
        text = await file.text();
    } catch {
        return toastError("The file could not be read.");
    }

    openPasswordPrompt({
        title: "Restore vault backup",
        description: "Password of the backup. In \"Stored\" mode it also becomes this PC's vault password (you can change it later).",
        confirmText: "Restore",
        kind: "existing",
        async onSubmit(password) {
            const result = await importVaultBackup(text, password);
            toastSuccess(result.needsKeyFile
                ? "Backup restored. Now unlock with your key file (lock menu or plugin settings)."
                : "Backup restored and unlocked.");
        }
    });
}
