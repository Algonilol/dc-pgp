/*
 * DcPgp – dialogs of the key exchange: accept a key, key change, safety number
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Paragraph } from "@components/Paragraph";

import type { KeyMessageKind } from "../core/format";
import { formatFingerprint } from "../core/pgp";
import { formatSafetyNumber } from "../core/safetyNumber";
import { alertDialog, choose, confirmDialog } from "./dialogs";

const mono = { fontFamily: "var(--font-code, monospace)", userSelect: "text" as const };

function Fingerprint({ label, fpr }: { label: string; fpr: string; }) {
    return (
        <Paragraph>
            {label}
            <br />
            <code style={mono}>{formatFingerprint(fpr)}</code>
        </Paragraph>
    );
}

export type AcceptChoice = "accept" | "decline" | "block" | "later";

export function askAcceptKey(name: string, fpr: string, kind: KeyMessageKind): Promise<AcceptChoice> {
    return choose<AcceptChoice>(
        kind === "keyreq" ? `Key request from ${name}` : `Key from ${name}`,
        <>
            <Paragraph>{`${name} wants to chat encrypted. Accept their public key and verify it?`}</Paragraph>
            <Fingerprint label="Fingerprint:" fpr={fpr} />
            <Paragraph>Accepting does not prove yet that the key is genuine: Discord carried it. Compare your safety numbers afterwards.</Paragraph>
        </>,
        [
            { label: "Decline", value: "decline" },
            { label: "Block", value: "block", variant: "critical-primary" },
            { label: "Accept & verify", value: "accept", variant: "primary" }
        ],
        "later"
    );
}

export function askResend(name: string): Promise<boolean> {
    return confirmDialog(
        `${name} asks for your key again`,
        `You are already connected. Maybe ${name} set up the mod again and lost your key. Send your public key again?`,
        "Send",
        "Don't send"
    );
}

export type ChangeChoice = "accept" | "reject" | "later";

export function askKeyChange(name: string, oldFpr: string, newFpr: string): Promise<ChangeChoice> {
    return choose<ChangeChoice>(
        `New key from ${name}`,
        <>
            <Paragraph>{`${name} sent a different key than the stored one. This happens after setting up again, but it can also be an attack. Only accept it if ${name} confirmed it to you another way (phone, in person).`}</Paragraph>
            <Fingerprint label="Stored:" fpr={oldFpr} />
            <Fingerprint label="New:" fpr={newFpr} />
            <Paragraph>{`Until you decide, nothing is encrypted to ${name} anymore.`}</Paragraph>
        </>,
        [
            { label: "Reject", value: "reject" },
            { label: "Later", value: "later" },
            { label: "Accept new key", value: "accept", variant: "critical-primary" }
        ],
        "later"
    );
}

export type VerifyChoice = "match" | "mismatch" | "later";

export function showSafetyNumber(name: string, safetyNumber: string, verified: boolean): Promise<VerifyChoice> {
    const groups = formatSafetyNumber(safetyNumber);
    const rows = [groups.slice(0, 4), groups.slice(4, 8), groups.slice(8, 12)];
    return choose<VerifyChoice>(
        `Safety number with ${name}`,
        <>
            <Paragraph>{`Compare these 60 digits once over a channel other than Discord: by phone, in person or via Signal. ${name} sees exactly the same number.`}</Paragraph>
            <div style={{ ...mono, fontSize: "1.15em", lineHeight: 1.7, textAlign: "center", margin: "12px 0" }}>
                {rows.map((row, i) => <div key={i}>{row.join("  ")}</div>)}
            </div>
            {verified && <Paragraph>{`${name} is already verified.`}</Paragraph>}
        </>,
        [
            { label: "Later", value: "later" },
            { label: "Doesn't match", value: "mismatch", variant: "critical-primary" },
            { label: "They match", value: "match", variant: "primary" }
        ],
        "later"
    );
}

export function warnMismatch(name: string): Promise<void> {
    return alertDialog(
        "Safety number does not match",
        `The stored key of ${name} may not be genuine (man-in-the-middle). Don't write anything confidential to ${name}, remove the contact and exchange keys again, ideally in person.`
    );
}

export function confirmRemoveContact(name: string): Promise<boolean> {
    return confirmDialog(
        `Remove contact ${name}?`,
        `Encryption in this chat will be turned off. You can exchange keys again at any time. The stored key of ${name} will be deleted, so old messages from ${name} can no longer be checked.`,
        "Remove",
        "Cancel",
        true
    );
}
