/*
 * DcPgp simulation – the plugin's ui/keyDialogs.tsx, answered the way sim/world.ts's policy says. The safety
 * numbers each account was shown are recorded, so the run can check that both saw the same 60 digits.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { currentUser, dialogs, policy, safetyNumbers } from "../world";

export type AcceptChoice = "accept" | "decline" | "block" | "later";
export type ChangeChoice = "accept" | "reject" | "later";
export type VerifyChoice = "match" | "mismatch" | "later";

export function askAcceptKey(name: string, _fpr: string, kind: string): Promise<AcceptChoice> {
    dialogs.push({ title: `Key ${kind} from ${name}`, answer: policy.acceptKey });
    return Promise.resolve(policy.acceptKey as AcceptChoice);
}

export const askResend = (_name: string) => Promise.resolve(true);

export function askKeyChange(name: string, _oldFpr: string, _newFpr: string): Promise<ChangeChoice> {
    dialogs.push({ title: `New key of ${name}`, answer: policy.keyChange });
    return Promise.resolve(policy.keyChange as ChangeChoice);
}

export function showSafetyNumber(name: string, safetyNumber: string, _verified: boolean): Promise<VerifyChoice> {
    safetyNumbers.push({ viewer: currentUser().id, name, number: safetyNumber });
    return Promise.resolve(policy.verify as VerifyChoice);
}

export const warnMismatch = (_name: string) => Promise.resolve();
export const confirmRemoveContact = (_name: string) => Promise.resolve(true);
