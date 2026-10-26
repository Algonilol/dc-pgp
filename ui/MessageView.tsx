/*
 * DcPgp – what we render under a message (Vencord message accessory): the decrypted text in place of
 * the hidden PGP block, a placeholder while locked, or the "not encrypted" mark. Decisions: core/display.ts.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, TextButton } from "@components/Button";
import { find } from "@webpack";
import { ChannelStore, EditMessageStore, Parser, Tooltip, useEffect, useLayoutEffect, useState, useStateFromStores } from "@webpack/common";
import type { ReactNode } from "react";

import { formatSize, isEncryptedFileName } from "../core/attachments";
import { canViewRawPgp, effectiveAutoDecrypt, hidesOriginal, messageDisplay, type PlaceholderReason, shouldMarkUnencrypted } from "../core/display";
import { type KeyCardActionId, keyCardModel } from "../core/exchange";
import { type KeyMessageKind, parseContent, snowflakeToMs } from "../core/format";
import { formatFingerprint } from "../core/pgp";
import { type DecryptedView, markRepeated } from "../core/receive";
import { type DiscordAttachment, openAttachment, type OpenedFile, saveOpenedFile } from "../discord/attachments";
import { type DecryptEntry, isRepeatedMessage, type MessageLike, revealMessage, useDecryption } from "../discord/decrypt";
import { channelKind, nameOf } from "../discord/discordUtils";
import { hideEncryptedFileCards, hideOriginalContent } from "../discord/hide";
import { actOnKeyMessage, checkOfferedKey, type KeyCheck, openVerifyDialog } from "../discord/keyExchange";
import { myId, useDcPgpState } from "../discord/state";
import { settings } from "../settings";
import { errorText } from "./common";
import { toastError, toastSuccess } from "./dialogs";
import { LockIcon } from "./icons";
import { openRawCiphertextModal, RawCiphertextView } from "./RawCiphertextView";
import { openSetupModal } from "./SetupModal";
import { requestUnlock } from "./UnlockModal";

interface AccessoryMessage extends MessageLike {
    type?: number;
    attachments?: DiscordAttachment[];
}

const isMarkupClass = (v: unknown): v is string => typeof v === "string" && /^markup_[\w-]+$/.test(v);
let markupClass: string | undefined;

/** Discord's class for formatted message text (code blocks, quotes, lists). Its key is minified, so we match the value. */
function getMarkupClass(): string {
    if (markupClass === undefined) {
        try {
            const mod = find(m => {
                try {
                    return typeof m === "object" && m !== null && Object.values(m).some(isMarkupClass);
                } catch {
                    return false;
                }
            }, { isIndirect: true });
            markupClass = mod ? Object.values(mod).find(isMarkupClass) ?? "" : "";
        } catch {
            markupClass = "";
        }
    }
    return markupClass;
}

const sentAt = (id: string) => /^\d{1,25}$/.test(id) ? snowflakeToMs(id) : Date.now();

const PLACEHOLDER_TEXT: Record<PlaceholderReason, string> = {
    loading: "Encrypted message",
    nosetup: "Encrypted message – DcPgp is not set up.",
    locked: "Encrypted message – DcPgp is locked.",
    manual: "Encrypted message"
};

function Note({ text, children }: { text: string; children?: ReactNode; }) {
    return (
        <div className="dcpgp-note">
            <LockIcon state="unavailable" closed width={14} height={14} />
            <span>{text}</span>
            {children}
        </div>
    );
}

function Placeholder({ reason, messageId, onViewRaw }: { reason: PlaceholderReason; messageId: string; onViewRaw?: () => void; }) {
    return (
        <Note text={PLACEHOLDER_TEXT[reason]}>
            {reason === "locked" && <TextButton variant="link" onClick={() => requestUnlock()}>Unlock</TextButton>}
            {onViewRaw && <TextButton variant="link" onClick={() => onViewRaw()}>View Raw PGP</TextButton>}
            {reason === "nosetup" && <TextButton variant="link" onClick={() => openSetupModal()}>Set up</TextButton>}
            {reason === "manual" && <TextButton variant="link" onClick={() => revealMessage(messageId)}>Decrypt</TextButton>}
        </Note>
    );
}

function TrustBadge({ view }: { view: DecryptedView; }) {
    const state = view.trust === "verified" ? "on" : view.trust === "failed" ? "warning" : "off";
    const title = view.trust === "verified" ? "End-to-end encrypted · sender verified"
        : view.trust === "failed" ? "End-to-end encrypted · check failed"
            : view.findings.some(f => f.level === "warning") ? "End-to-end encrypted · see the warning"
                : "End-to-end encrypted · sender not verified";
    const notes = view.findings.filter(f => f.level === "info");
    return (
        <Tooltip text={<>{title}{notes.map(f => <div key={f.code}>{f.text}</div>)}</>}>
            {props => (
                <span {...props} className="dcpgp-badge">
                    <LockIcon state={state} closed width={14} height={14} />
                </span>
            )}
        </Tooltip>
    );
}

function Decrypted({ entry, message, blur, repeated }: { entry: DecryptEntry | null; message: AccessoryMessage; blur: boolean; repeated: boolean; }) {
    if (!entry || entry.status === "pending" || entry.status === "locked") return <Note text="Decrypting …" />;
    if (entry.status === "not-for-us") return <Note text="Encrypted message – not encrypted to your key." />;
    if (entry.status === "error" || !entry.view)
        return <div className="dcpgp-alert">⚠ This encrypted message is damaged or was altered and cannot be opened.</div>;

    const view = repeated ? markRepeated(entry.view) : entry.view;
    const errors = view.findings.filter(f => f.level === "error");
    const warnings = view.findings.filter(f => f.level === "warning");
    const className = [getMarkupClass(), "dcpgp-plain", blur && "dcpgp-blur", errors.length > 0 && "dcpgp-failed"].filter(Boolean).join(" ");
    return (
        <div>
            {errors.length > 0 && <div className="dcpgp-alert">⚠ {errors.map(f => f.text).join(" ")}</div>}
            <div className={className}>
                {Parser.parse(view.text, true, { channelId: message.channel_id, messageId: message.id, allowLinks: true, allowEmojiLinks: true, allowHeading: true, allowList: true })}
                <TrustBadge view={view} />
                {message.editedTimestamp ? <span className="dcpgp-edited">(edited)</span> : null}
            </div>
            <EncryptedFiles message={message} view={view} blur={blur} />
            {warnings.map(f => <div key={f.code} className="dcpgp-warning">⚠ {f.text}</div>)}
        </div>
    );
}

/** One encrypted file of a decrypted message: downloaded, checked against the message and decrypted, in memory only. */
function FileView({ message, view, attachment, blur }: { message: AccessoryMessage; view: DecryptedView; attachment: DiscordAttachment; blur: boolean; }) {
    const [file, setFile] = useState<OpenedFile | null>(null);
    const [force, setForce] = useState(false);
    useEffect(() => {
        let alive = true;
        setFile(null);
        openAttachment(message, view, attachment, force).then(f => { if (alive) setFile(f); });
        return () => { alive = false; };
    }, [message.id, attachment.id, view.contentId, view.signerFpr, view.trust === "failed", force]);

    if (!file) return <Note text="Decrypting file …" />;
    if (file.status === "error") return <div className="dcpgp-alert">⚠ {file.message}</div>;
    if (file.status === "large")
        return (
            <div className="dcpgp-file">
                <span className="dcpgp-file-name">Encrypted file</span>
                <span className="dcpgp-file-meta">{formatSize(file.size)}</span>
                <TextButton variant="link" onClick={() => setForce(true)}>Decrypt</TextButton>
            </div>
        );

    const media = [
        "dcpgp-media",
        blur && "dcpgp-blur"
    ].filter(Boolean).join(" ");
    const save = () => saveOpenedFile(file)
        .then(path => { if (path) toastSuccess(`Saved: ${path}`); })
        .catch(e => toastError(errorText(e)));
    return (
        <>
            {file.kind === "image" && <img className={media} src={file.url} alt={file.name} />}
            {file.kind === "video" && <video className={media} src={file.url} controls preload="metadata" />}
            {file.kind === "audio" && <audio src={file.url} controls preload="metadata" />}
            <div className="dcpgp-file">
                <span className="dcpgp-file-name">{file.name}</span>
                <span className="dcpgp-file-meta">{formatSize(file.size)} · end-to-end encrypted</span>
                <TextButton variant="link" onClick={save}>Save …</TextButton>
            </div>
            {file.note && <div className="dcpgp-warning">⚠ {file.note}</div>}
        </>
    );
}

/** The message's encrypted files in place of Discord's cards for dcpgp-N.pgp. */
function EncryptedFiles({ message, view, blur }: { message: AccessoryMessage; view: DecryptedView; blur: boolean; }) {
    const files = (message.attachments ?? []).filter(a => isEncryptedFileName(a?.filename));
    const listed = view.meta?.attachments?.length ?? 0;
    useLayoutEffect(() => files.length ? hideEncryptedFileCards(message.id) : undefined, [message.id, files.length > 0]);
    if (!files.length && !listed) return null;
    return (
        <div className="dcpgp-attachments">
            {files.map(a => <FileView key={a.id} message={message} view={view} attachment={a} blur={blur} />)}
            {listed > files.length && <div className="dcpgp-warning">⚠ {listed - files.length} of the message's files are missing.</div>}
        </div>
    );
}

/** Replaces the raw key block of a key request/response with the offer and one-click actions. */
function KeyMessageCard({ message, kind, armoredKey }: { message: AccessoryMessage; kind: KeyMessageKind; armoredKey: string; }) {
    const s = useDcPgpState();
    const [check, setCheck] = useState<KeyCheck | undefined>(undefined);
    const [busy, setBusy] = useState(false);
    useEffect(() => {
        let alive = true;
        setCheck(undefined);
        checkOfferedKey(armoredKey).then(r => { if (alive) setCheck(r); });
        return () => { alive = false; };
    }, [armoredKey]);

    const channel = ChannelStore.getChannel(message.channel_id);
    const authorId = message.author?.id ?? "";
    const model = keyCardModel({
        phase: s.phase,
        kind,
        messageId: message.id,
        authorId,
        authorName: nameOf(authorId, channel?.guild_id),
        myId: myId(),
        isDm: channelKind(channel) === "dm",
        check,
        data: s.session?.data ?? null
    });

    function run(id: KeyCardActionId) {
        if (id === "unlock") return requestUnlock();
        if (id === "setup") return openSetupModal();
        // "review" goes through "accept": a different key always opens the key-change dialog first.
        const work = id === "verify"
            ? openVerifyDialog(authorId)
            : actOnKeyMessage(message, id === "decline" ? "decline" : id === "resend" ? "resend" : "accept");
        setBusy(true);
        work.finally(() => setBusy(false));
    }

    return (
        <div className={`dcpgp-keycard dcpgp-tone-${model.tone}`}>
            <span>🔑 {model.text}</span>
            {model.actions.map(a => (
                <Button key={a.id} size="small" variant={a.id === "accept" ? "primary" : "secondary"} disabled={busy} onClick={() => run(a.id)}>
                    {a.label}
                </Button>
            ))}
            {model.fpr && <code className="dcpgp-fpr">Fingerprint: {formatFingerprint(model.fpr)}</code>}
        </div>
    );
}

function UnencryptedMark() {
    return (
        <Tooltip text="This message is not end-to-end encrypted, although the chat is. Discord can read it.">
            {props => (
                <span {...props} className="dcpgp-unencrypted">
                    <LockIcon state="off" closed={false} width={12} height={12} />
                    not encrypted
                </span>
            )}
        </Tooltip>
    );
}

function MessageAccessory({ message }: { message: AccessoryMessage; }) {
    const s = useDcPgpState();
    const opts = settings.use(["markUnencrypted", "autoDecrypt", "blurPlaintext", "showRawCiphertextWhenLocked"]);
    const parsed = parseContent(message.content);
    const pref = s.session?.data.channels[message.channel_id];
    const display = messageDisplay({
        phase: s.phase,
        kind: parsed.kind,
        autoDecrypt: effectiveAutoDecrypt(opts.autoDecrypt, pref),
        revealed: s.revealed.has(message.id),
        showRawWhenLocked: opts.showRawCiphertextWhenLocked,
        markUnencrypted: shouldMarkUnencrypted({
            enabled: opts.markUnencrypted,
            phase: s.phase,
            pref,
            kind: parsed.kind,
            messageType: message.type ?? 0,
            sentAtMs: sentAt(message.id)
        })
    });
    const armored = parsed.kind === "message" ? parsed.armored : null;
    const entry = useDecryption(message, display.kind === "decrypt" ? armored : null);
    const repeated = display.kind === "decrypt" && entry?.status === "ok" && entry.view != null && isRepeatedMessage(message, entry.view);
    // While the message is being edited, its text is in Discord's edit box: not twice.
    const editing = useStateFromStores([EditMessageStore], () => EditMessageStore.isEditing(message.channel_id, message.id));
    const viewRaw = armored && canViewRawPgp(display, channelKind(ChannelStore.getChannel(message.channel_id)))
        ? () => openRawCiphertextModal(armored)
        : undefined;
    const hide = hidesOriginal(display);
    // Layout effect: the CSS rule is in place before the browser paints the PGP block.
    useLayoutEffect(() => hide ? hideOriginalContent(message.channel_id, message.id) : undefined, [hide, message.channel_id, message.id]);

    switch (display.kind) {
        case "none":
            return null;
        case "unencrypted":
            return <UnencryptedMark />;
        case "placeholder":
            return <Placeholder reason={display.reason} messageId={message.id} onViewRaw={viewRaw} />;
        case "decrypt":
            return editing ? null : <Decrypted entry={entry} message={message} blur={opts.blurPlaintext} repeated={repeated} />;
        case "key":
            return parsed.kind === "keyreq" || parsed.kind === "keyresp"
                ? <KeyMessageCard message={message} kind={parsed.kind} armoredKey={parsed.armoredKey} />
                : null;
        case "raw":
            return <RawCiphertextView raw={message.content ?? ""} label={PLACEHOLDER_TEXT.locked} onUnlock={() => requestUnlock()} onViewRaw={viewRaw} />;
    }
}

/** Registered with Vencord's message accessories; returns an element so our hooks live in their own component. */
export function renderMessageAccessory(props: Record<string, any>) {
    const message = props?.message;
    if (typeof message?.id !== "string" || typeof message.channel_id !== "string") return null;
    return <MessageAccessory message={message} />;
}
