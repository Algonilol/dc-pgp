/*
 * DcPgp – unlock dialog: vault password, or key file + passphrase ("RAM only" mode / recovery)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, TextButton } from "@components/Button";
import { Paragraph } from "@components/Paragraph";
import { chooseFile } from "@utils/web";
import type { RenderModalProps } from "@vencord/discord-types";
import { Forms, Modal, openModal, TextInput, useState } from "@webpack/common";
import type { KeyboardEvent } from "react";

import { readKeyFile, unlockVault } from "../discord/actions";
import { S } from "../discord/state";
import { ErrorText, errorText, Gap, shortName } from "./common";
import { toastSuccess } from "./dialogs";
import { openChangePasswordModal } from "./vaultFlows";

const KEY_FILE_TYPES = ".asc,.gpg,.key,.pgp,.txt";

function UnlockModal(props: RenderModalProps) {
    const isRam = S.file?.mode === "ram";
    const [useKeyFile, setUseKeyFile] = useState(isRam);
    const [password, setPassword] = useState("");
    const [keyFile, setKeyFile] = useState<{ name: string; content: string | Uint8Array; } | null>(null);
    const [passphrase, setPassphrase] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const ready = useKeyFile ? keyFile != null && passphrase.length > 0 : password.length > 0;

    async function pickFile() {
        setError(null);
        try {
            const file = await chooseFile(KEY_FILE_TYPES);
            if (file) setKeyFile({ name: file.name, content: await readKeyFile(file) });
        } catch (e) {
            setError(errorText(e));
        }
    }

    async function submit() {
        if (!ready || busy) return;
        setBusy(true);
        setError(null);
        try {
            const result = await unlockVault(useKeyFile ? { keyFile: keyFile!.content, passphrase } : { password });
            props.onClose();
            toastSuccess("DcPgp unlocked.");
            if (result.viaKeyFile && S.file?.mode === "stored")
                openChangePasswordModal("Set a new password", "You unlocked with your key file. Set a new vault password for this PC now (or later in the plugin settings).");
        } catch (e) {
            setError(errorText(e));
            setBusy(false);
        }
    }

    const onEnter = (e: KeyboardEvent) => { if (e.key === "Enter") void submit(); };

    return (
        <Modal
            {...props}
            title="Unlock DcPgp"
            actions={[
                { text: "Continue without encryption", variant: "secondary", onClick: () => props.onClose() },
                { text: "Unlock", variant: "primary", onClick: () => void submit(), loading: busy, disabled: !ready || busy }
            ]}
        >
            {useKeyFile ? (
                <>
                    <Paragraph>
                        {isRam
                            ? "\"RAM only\" mode: choose your key file (Kleopatra export or DcPgp key file) and enter its passphrase."
                            : "Recovery: choose your key file and enter its passphrase."}
                    </Paragraph>
                    <Gap />
                    <Button size="small" variant="secondary" onClick={() => void pickFile()}>
                        {keyFile ? `File: ${shortName(keyFile.name)}` : "Choose key file …"}
                    </Button>
                    <Gap />
                    <Forms.FormTitle tag="h5">Passphrase of the key file</Forms.FormTitle>
                    <TextInput type="password" value={passphrase} onChange={setPassphrase} onKeyDown={onEnter} />
                </>
            ) : (
                <>
                    <Paragraph>Enter your vault password. Until you unlock, encrypted messages stay ciphertext and you cannot send anything in encrypted chats.</Paragraph>
                    <Gap />
                    <Forms.FormTitle tag="h5">Password</Forms.FormTitle>
                    <TextInput type="password" value={password} autoFocus onChange={setPassword} onKeyDown={onEnter} />
                </>
            )}
            {error && <ErrorText>{error}</ErrorText>}
            {!isRam && (
                <>
                    <Gap size={8} />
                    {/* Vencord's text buttons don't wrap (white-space: nowrap); this long label overflowed and caused a horizontal scrollbar. */}
                    <TextButton variant="link" style={{ whiteSpace: "normal", textAlign: "start" }} onClick={() => { setUseKeyFile(!useKeyFile); setError(null); }}>
                        {useKeyFile ? "Unlock with password" : "Forgot your password or new PC? Unlock with your key file"}
                    </TextButton>
                </>
            )}
        </Modal>
    );
}

let open = false;

export function openUnlockModal() {
    if (open || S.phase !== "locked") return;
    open = true;
    openModal(props => <UnlockModal {...props} />, { onCloseCallback: () => { open = false; } });
}
