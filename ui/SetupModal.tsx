/*
 * DcPgp – first-time setup: key (generate or import from Kleopatra) → mode → password → key file → done
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button } from "@components/Button";
import { Paragraph } from "@components/Paragraph";
import { chooseFile } from "@utils/web";
import type { ModalAction, RenderModalProps } from "@vencord/discord-types";
import { Forms, Modal, openModal, TextInput, UserStore, useState } from "@webpack/common";
import type { ReactNode } from "react";

import { formatFingerprint, type KeyReport } from "../core/pgp";
import type { VaultMode } from "../core/vault";
import { setupNeeds } from "../core/vaultOps";
import { type PreparedKey, prepareGeneratedKey, prepareImportedKey, readKeyFile, saveKeyFile, setupVault } from "../discord/actions";
import { S } from "../discord/state";
import { COLORS, ErrorText, errorText, Gap, mono, shortName } from "./common";
import { toastSuccess } from "./dialogs";
import { NewPasswordFields, useNewPassword } from "./passwordFields";

type Step = "source" | "generate" | "import" | "mode" | "password" | "keyfile";

function defaultName(): string {
    const user = UserStore.getCurrentUser();
    return user?.globalName || user?.username || "Discord";
}

function KeyReportView({ report }: { report: KeyReport; }) {
    return (
        <div>
            <Paragraph>
                {report.primaryUserId || "(no name)"} · {report.algorithm}{report.encryptionAlgorithm ? ` / ${report.encryptionAlgorithm}` : ""}
                {report.expires ? ` · expires on ${report.expires.toISOString().slice(0, 10)}` : ""}
            </Paragraph>
            <Paragraph>Fingerprint: <span style={mono}>{formatFingerprint(report.fingerprint)}</span></Paragraph>
            {report.warnings.map(w => <Paragraph key={w} style={{ color: COLORS.warn, marginTop: 6 }}>⚠ {w}</Paragraph>)}
            {report.errors.map(e => <Paragraph key={e} style={{ color: COLORS.bad, marginTop: 6 }}>✖ {e}</Paragraph>)}
        </div>
    );
}

function Choice({ title, text, selected, onClick }: { title: string; text: string; selected: boolean; onClick(): void; }) {
    return (
        <Button variant={selected ? "primary" : "secondary"} onClick={onClick} style={{ width: "100%", height: "auto", padding: "10px 12px", textAlign: "left", marginBottom: 8 }}>
            <div>
                <div style={{ fontWeight: 600 }}>{title}</div>
                <div style={{ fontWeight: 400, opacity: 0.85, whiteSpace: "normal" }}>{text}</div>
            </div>
        </Button>
    );
}

function SetupModal(props: RenderModalProps) {
    const [step, setStep] = useState<Step>("source");
    const [name, setName] = useState(defaultName);
    const [importFile, setImportFile] = useState<{ name: string; content: string | Uint8Array; } | null>(null);
    const [gpgPassphrase, setGpgPassphrase] = useState("");
    const [prepared, setPrepared] = useState<PreparedKey | null>(null);
    const [mode, setMode] = useState<VaultMode>("stored");
    const np = useNewPassword();
    const [savedPath, setSavedPath] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const needs = prepared ? setupNeeds(prepared.source, mode) : null;

    async function run(fn: () => Promise<void>) {
        setBusy(true);
        setError(null);
        try {
            await fn();
        } catch (e) {
            setError(errorText(e));
        } finally {
            setBusy(false);
        }
    }

    const finish = () => run(async () => {
        await setupVault({
            prepared: prepared!,
            mode,
            password: needs?.password ? np.state.password : undefined,
            generatedPassword: np.state.generated,
            keyFileSaved: savedPath != null
        });
        props.onClose();
        toastSuccess("Discord-PGP is set up. Now request someone's key via the lock menu in a chat or by right-clicking them.");
    });

    const afterMode = () => needs?.password ? setStep("password") : needs?.keyFile ? setStep("keyfile") : void finish();
    const afterPassword = () => needs?.keyFile ? setStep("keyfile") : void finish();

    const back = (to: Step): ModalAction => ({ text: "Back", variant: "secondary", onClick: () => { setError(null); setStep(to); }, disabled: busy });
    const cancel: ModalAction = { text: "Cancel", variant: "secondary", onClick: () => props.onClose() };

    let body: ReactNode;
    let actions: ModalAction[];

    switch (step) {
        case "source":
            body = (
                <>
                    <Paragraph>Discord-PGP encrypts your messages end-to-end. For that you need your own PGP key.</Paragraph>
                    <Gap />
                    <Choice title="Generate a new key" text="Recommended if you don't have a key just for Discord yet (Curve25519, valid for 2 years)." selected={false} onClick={() => setStep("generate")} />
                    <Choice title="Import a key from Kleopatra" text="An exported file with your secret key (.asc/.gpg) and its passphrase." selected={false} onClick={() => setStep("import")} />
                </>
            );
            actions = [cancel];
            break;

        case "generate":
            body = (
                <>
                    <Paragraph>The name is stored in the key and visible to your contacts. Use your Discord name, not an email address.</Paragraph>
                    <Gap />
                    <Forms.FormTitle tag="h5">Name in the key</Forms.FormTitle>
                    <TextInput value={name} onChange={setName} maxLength={64} />
                </>
            );
            actions = [back("source"), {
                text: "Generate key", variant: "primary", loading: busy, disabled: busy || !name.trim(),
                onClick: () => void run(async () => { setPrepared(await prepareGeneratedKey(name)); setSavedPath(null); setStep("mode"); })
            }];
            break;

        case "import":
            body = (
                <>
                    <Paragraph>In Kleopatra: right-click your key → "Backup Secret Keys…" ("Export Secret Keys" in older versions). Recommended: a Curve25519 key just for Discord, without an email address.</Paragraph>
                    <Gap />
                    <Button size="small" variant="secondary" onClick={() => void run(async () => {
                        const file = await chooseFile(".asc,.gpg,.key,.pgp,.txt");
                        if (file) {
                            setImportFile({ name: file.name, content: await readKeyFile(file) });
                            setPrepared(null);
                        }
                    })}>
                        {importFile ? `File: ${shortName(importFile.name)}` : "Choose key file …"}
                    </Button>
                    <Gap />
                    <Forms.FormTitle tag="h5">Passphrase of the key</Forms.FormTitle>
                    <TextInput type="password" value={gpgPassphrase} onChange={v => { setGpgPassphrase(v); setPrepared(null); }} />
                    {prepared && <><Gap /><KeyReportView report={prepared.report} /></>}
                </>
            );
            actions = [back("source"), prepared
                ? { text: "Next", variant: "primary", disabled: busy || prepared.report.errors.length > 0, onClick: () => setStep("mode") }
                : {
                    text: "Check", variant: "primary", loading: busy, disabled: busy || !importFile || !gpgPassphrase,
                    onClick: () => void run(async () => setPrepared(await prepareImportedKey(importFile!.content, gpgPassphrase)))
                }];
            break;

        case "mode":
            body = (
                <>
                    {prepared && <KeyReportView report={prepared.report} />}
                    <Gap />
                    <Choice title="Stored (recommended)" text="Your key is kept encrypted on this PC, protected by your password and the Windows device key. On startup, the password is enough." selected={mode === "stored"} onClick={() => setMode("stored")} />
                    <Choice title="RAM only" text="Nothing secret on disk. Every time Discord starts, you need the key file and its passphrase." selected={mode === "ram"} onClick={() => setMode("ram")} />
                </>
            );
            actions = [back(prepared?.source === "import" ? "import" : "generate"), { text: "Next", variant: "primary", loading: busy, disabled: busy, onClick: afterMode }];
            break;

        case "password":
            body = (
                <>
                    <Paragraph>
                        {mode === "stored"
                            ? "This password unlocks Discord-PGP every time Discord starts. It cannot be reset – only recovered with your key file."
                            : "This password protects your key file. You need it every time Discord starts."}
                    </Paragraph>
                    <Gap />
                    <NewPasswordFields np={np} label={mode === "stored" ? "Vault password" : "Password of the key file"} />
                </>
            );
            actions = [back("mode"), { text: needs?.keyFile ? "Next" : "Set up", variant: "primary", loading: busy, disabled: busy || !np.valid, onClick: afterPassword }];
            break;

        case "keyfile":
            body = (
                <>
                    <Paragraph>So far your new key only exists here. Save it as a file, protected with the password you just chose. You can import it into Kleopatra; in "RAM only" mode you unlock with it.</Paragraph>
                    <Gap />
                    <Button size="small" variant={savedPath ? "secondary" : "primary"} disabled={busy} onClick={() => void run(async () => {
                        const path = await saveKeyFile(prepared!.key, np.state.password, np.state.generated);
                        if (path) setSavedPath(path);
                    })}>
                        {savedPath ? "Save again …" : "Save key file …"}
                    </Button>
                    {savedPath && <Paragraph style={{ color: COLORS.ok, marginTop: 6 }}>Saved: {savedPath}</Paragraph>}
                </>
            );
            actions = [back("password"), { text: "Finish setup", variant: "primary", loading: busy, disabled: busy || !savedPath, onClick: () => void finish() }];
            break;
    }

    return (
        <Modal {...props} title="Set up Discord-PGP" actions={actions}>
            {body}
            {error && <ErrorText>{error}</ErrorText>}
        </Modal>
    );
}

let open = false;

export function openSetupModal() {
    if (open || S.phase !== "nosetup") return;
    open = true;
    openModal(props => <SetupModal {...props} />, { onCloseCallback: () => { open = false; } });
}
