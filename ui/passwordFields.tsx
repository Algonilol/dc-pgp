/*
 * DcPgp – password input with generator and conservative strength check, plus a generic password dialog
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, TextButton } from "@components/Button";
import { Paragraph } from "@components/Paragraph";
import type { RenderModalProps } from "@vencord/discord-types";
import { Forms, Modal, openModal, TextInput, useEffect, useState } from "@webpack/common";
import type { ReactNode } from "react";

import { MIN_BITS, type StrengthResult } from "../core/strength";
import { checkPassword, newPassphrase } from "../discord/actions";
import { COLORS, ErrorText, errorText, Gap, mono } from "./common";

export interface NewPasswordState {
    password: string;
    confirm: string;
    generated: string | null;
}

function useStrength(password: string, generated: string | null): StrengthResult | null {
    const [result, setResult] = useState<StrengthResult | null>(null);
    useEffect(() => {
        if (!password) {
            setResult(null);
            return;
        }
        let cancelled = false;
        const timer = setTimeout(() => {
            checkPassword(password, generated)
                .then(r => { if (!cancelled) setResult(r); })
                .catch(() => { if (!cancelled) setResult(null); });
        }, 250);
        return () => {
            cancelled = true;
            clearTimeout(timer);
        };
    }, [password, generated]);
    return result;
}

export function useNewPassword() {
    const [state, setState] = useState<NewPasswordState>({ password: "", confirm: "", generated: null });
    const strength = useStrength(state.password, state.generated);
    const matches = state.generated != null ? state.password === state.generated : state.password === state.confirm;
    const valid = state.password.length > 0 && matches && strength?.ok === true;
    return { state, setState, strength, valid };
}

export type NewPassword = ReturnType<typeof useNewPassword>;

export function NewPasswordFields({ np, label = "Password" }: { np: NewPassword; label?: string; }) {
    const { state, setState, strength } = np;
    const [visible, setVisible] = useState(false);

    return (
        <div>
            <Forms.FormTitle tag="h5">{label}</Forms.FormTitle>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <div style={{ flex: 1 }}>
                    <TextInput
                        type={visible ? "text" : "password"}
                        value={state.password}
                        placeholder="5 or more random words"
                        onChange={v => setState({ password: v, confirm: state.confirm, generated: null })}
                    />
                </div>
                <Button size="small" variant="secondary" onClick={() => {
                    const p = newPassphrase();
                    setState({ password: p, confirm: p, generated: p });
                    setVisible(true);
                }}>
                    Generate
                </Button>
            </div>
            {state.generated && (
                <Paragraph style={{ marginTop: 6 }}>
                    Generated: <span style={mono}>{state.generated}</span> – write it down on paper.
                </Paragraph>
            )}
            {strength && (
                <Paragraph style={{ color: strength.ok ? COLORS.ok : COLORS.bad, marginTop: 6 }}>
                    {strength.ok
                        ? `Strong enough (≈ ${Math.round(strength.bits)} bits).`
                        : `Too weak (≈ ${Math.round(strength.bits)} bits, ${Math.ceil(MIN_BITS)} needed).`}
                    {strength.warning ? ` ${strength.warning}` : ""}
                </Paragraph>
            )}
            {state.generated == null && (
                <>
                    <Gap size={8} />
                    <Forms.FormTitle tag="h5">Repeat password</Forms.FormTitle>
                    <TextInput type="password" value={state.confirm} onChange={v => setState({ ...state, confirm: v })} />
                    {state.confirm && state.confirm !== state.password && (
                        <Paragraph style={{ color: COLORS.bad, marginTop: 6 }}>The passwords don't match.</Paragraph>
                    )}
                </>
            )}
            <TextButton variant="secondary" onClick={() => setVisible(!visible)}>{visible ? "Hide password" : "Show password"}</TextButton>
        </div>
    );
}

export interface PasswordPromptOptions {
    title: string;
    description?: ReactNode;
    confirmText: string;
    /** "new" asks for a new strong password (with repeat and generator), "existing" for a known one. */
    kind: "new" | "existing";
    onSubmit(password: string, generated: string | null): Promise<void>;
}

function PasswordPromptModal({ o, ...props }: RenderModalProps & { o: PasswordPromptOptions; }) {
    const np = useNewPassword();
    const [existing, setExisting] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const canSubmit = o.kind === "new" ? np.valid : existing.length > 0;

    async function submit() {
        if (!canSubmit || busy) return;
        setBusy(true);
        setError(null);
        try {
            await o.onSubmit(o.kind === "new" ? np.state.password : existing, o.kind === "new" ? np.state.generated : null);
            props.onClose();
        } catch (e) {
            setError(errorText(e));
            setBusy(false);
        }
    }

    return (
        <Modal
            {...props}
            title={o.title}
            actions={[
                { text: "Cancel", variant: "secondary", onClick: () => props.onClose() },
                { text: o.confirmText, variant: "primary", onClick: () => void submit(), loading: busy, disabled: !canSubmit || busy }
            ]}
        >
            {typeof o.description === "string" ? <Paragraph>{o.description}</Paragraph> : o.description}
            <Gap />
            {o.kind === "new"
                ? <NewPasswordFields np={np} />
                : <TextInput type="password" value={existing} autoFocus onChange={setExisting} onKeyDown={e => { if (e.key === "Enter") void submit(); }} />}
            {error && <ErrorText>{error}</ErrorText>}
        </Modal>
    );
}

export function openPasswordPrompt(o: PasswordPromptOptions) {
    openModal(props => <PasswordPromptModal {...props} o={o} />);
}
