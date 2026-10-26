/*
 * DcPgp – status and vault actions shown on the plugin's settings page
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button } from "@components/Button";
import { Paragraph } from "@components/Paragraph";

import { formatFingerprint } from "../core/pgp";
import { privateKeyOptions } from "../core/vaultOps";
import { lockVault } from "../discord/actions";
import { useDcPgpState } from "../discord/state";
import { COLORS, Gap, mono } from "./common";
import { openSetupModal } from "./SetupModal";
import { requestUnlock } from "./UnlockModal";
import { openBackupExport, openChangePasswordModal, openKeyFileExport, openModeSwitch, openShowPrivateKey, openWindowsUnlockSwitch, startBackupImport } from "./vaultFlows";

const PHASE_TEXT = {
    loading: "Loading …",
    nosetup: "Not set up yet",
    locked: "Locked",
    unlocked: "Unlocked"
} as const;

export function SettingsPanel() {
    const s = useDcPgpState();
    const session = s.session;
    const mode = s.file?.mode;
    const keyOptions = privateKeyOptions(s.phase === "unlocked", mode);

    return (
        <div>
            <Paragraph>
                Status: <b>{PHASE_TEXT[s.phase]}</b>
                {mode && ` · Mode: ${mode === "stored" ? "Stored" : "RAM only"}`}
                {s.file?.w && " · unlocks with Windows"}
                {session && ` · ${Object.keys(session.data.contacts).length} contacts`}
            </Paragraph>
            {(session || s.file) && (
                <Paragraph>Your fingerprint: <span style={mono}>{formatFingerprint(session?.data.self.fpr ?? s.file!.ownFpr)}</span></Paragraph>
            )}
            {!s.hookHealthy && (
                <Paragraph style={{ color: COLORS.bad }}>Send protection broken: {s.hookProblem ?? "unknown"} Please update Vencord.</Paragraph>
            )}
            <Gap />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {s.phase === "nosetup" && <Button onClick={openSetupModal}>Set up</Button>}
                {s.phase === "locked" && <Button onClick={requestUnlock}>Unlock</Button>}
                {s.phase === "unlocked" && (
                    <>
                        <Button variant="secondary" onClick={() => lockVault("manually")}>Lock now</Button>
                        {mode === "stored" && <Button variant="secondary" onClick={() => openChangePasswordModal()}>Change password</Button>}
                        {mode === "stored" && (
                            <Button variant="secondary" onClick={() => void openWindowsUnlockSwitch()}>
                                {s.file?.w ? "Stop unlocking with Windows …" : "Unlock with Windows …"}
                            </Button>
                        )}
                        <Button variant="secondary" onClick={() => openKeyFileExport()}>Save key file</Button>
                        {keyOptions.show && <Button variant="secondary" onClick={openShowPrivateKey}>Show private key …</Button>}
                        {keyOptions.remove && <Button variant="dangerSecondary" onClick={() => void openModeSwitch()}>Remove stored private key …</Button>}
                        {keyOptions.store && <Button variant="secondary" onClick={() => void openModeSwitch()}>Store private key on this PC …</Button>}
                        <Button variant="secondary" onClick={openBackupExport}>Save vault backup</Button>
                    </>
                )}
                {s.phase !== "loading" && <Button variant="secondary" onClick={() => void startBackupImport()}>Restore vault backup</Button>}
            </div>
        </div>
    );
}
