/*
 * DcPgp – lock button next to the chat input and its menu (the "lock menu").
 * What it shows is decided by core/menus.ts (tested); this only renders it.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChatBarButton, type ChatBarButtonFactory } from "@api/ChatButtons";
import type { Channel } from "@vencord/discord-types";
import { ContextMenuApi, FluxDispatcher, Menu } from "@webpack/common";

import { contactStatus } from "../core/contacts";
import { effectiveAutoDecrypt } from "../core/display";
import { isKeyExpired, isKeyExpiringSoon } from "../core/keyLifetime";
import { chatButtonModel, type ChatMenuInput, type MenuEntry, shouldShowEncryptedDot } from "../core/menus";
import { lockVault } from "../discord/actions";
import { setChatAutoDecrypt } from "../discord/decrypt";
import { channelKind, dmPartnerId, nameOf, planForChannel } from "../discord/discordUtils";
import { actOnKeyMessage, findPendingOffer, openVerifyDialog, removeContactFlow, requestKey, reviewKeyChange, setChatEncrypted, toggleOneShot } from "../discord/keyExchange";
import { isChannelEncrypted, S, useDcPgpState } from "../discord/state";
import { settings } from "../settings";
import { COLORS } from "./common";
import { toastInfo } from "./dialogs";
import { LockIcon } from "./icons";
import { openSetupModal } from "./SetupModal";
import { openUnlockModal } from "./UnlockModal";

function menuInput(channel: Channel): ChatMenuInput {
    const kind = channelKind(channel);
    const session = S.session;
    const plan = session && kind !== "unsupported" ? planForChannel(channel) : null;
    const partnerId = kind === "dm" ? dmPartnerId(channel) : null;
    const keyExpires = partnerId ? session?.data.contacts[partnerId]?.keyExpires : undefined;
    const now = Date.now();
    return {
        phase: S.phase,
        kind,
        encrypted: isChannelEncrypted(channel.id),
        oneShot: S.oneShot.has(channel.id),
        autoDecrypt: effectiveAutoDecrypt(settings.store.autoDecrypt, session?.data.channels[channel.id]),
        hookHealthy: S.hookHealthy,
        visibilityUnknown: plan?.visibilityUnknown,
        readers: plan?.readers.map(r => ({ name: r.name, verified: r.contact.verified })) ?? [],
        missing: plan?.missing.map(m => ({ name: m.name, reason: m.reason })) ?? [],
        partner: session && partnerId
            ? {
                name: nameOf(partnerId),
                status: contactStatus(session.data, partnerId),
                outgoingPending: !!session.data.outgoing[partnerId],
                offer: findPendingOffer(channel.id, partnerId) != null,
                hasContact: !!session.data.contacts[partnerId],
                keyExpiring: isKeyExpiringSoon(keyExpires, now),
                keyExpired: isKeyExpired(keyExpires, now)
            }
            : undefined
    };
}

function runEntry(entry: MenuEntry, channel: Channel) {
    const partnerId = channelKind(channel) === "dm" ? dmPartnerId(channel) : null;
    switch (entry.id) {
        case "encrypt-all":
            if (entry.type === "toggle") void setChatEncrypted(channel.id, !entry.checked);
            return;
        case "encrypt-once":
            toggleOneShot(channel.id);
            return;
        case "auto-decrypt":
            if (entry.type === "toggle") void setChatAutoDecrypt(channel.id, !entry.checked);
            return;
        case "request-key":
        case "request-update":
            if (partnerId) void requestKey(partnerId);
            return;
        case "accept-key": {
            const offer = partnerId ? findPendingOffer(channel.id, partnerId) : null;
            if (offer) void actOnKeyMessage(offer, "accept");
            else toastInfo("The key message is no longer loaded. Scroll to it in the chat or request the key again.");
            return;
        }
        case "verify":
            if (partnerId) void openVerifyDialog(partnerId);
            return;
        case "review-change":
            if (partnerId) void reviewKeyChange(partnerId);
            return;
        case "remove-contact":
            if (partnerId) void removeContactFlow(partnerId, channel.id);
            return;
        case "setup":
            openSetupModal();
            return;
        case "unlock":
            openUnlockModal();
            return;
        case "lock":
            lockVault("manually");
            return;
    }
}

function LockMenu({ channel }: { channel: Channel; }) {
    useDcPgpState();
    const { entries } = chatButtonModel(menuInput(channel));
    return (
        <Menu.Menu navId="dcpgp-lock-menu" onClose={() => FluxDispatcher.dispatch({ type: "CONTEXT_MENU_CLOSE" } as any)}>
            {entries.map(entry => {
                switch (entry.type) {
                    case "toggle":
                        return <Menu.MenuCheckboxItem key={entry.id} id={`dcpgp-${entry.id}`} label={entry.label} checked={entry.checked} disabled={entry.disabled} action={() => runEntry(entry, channel)} />;
                    case "action":
                        return <Menu.MenuItem key={entry.id} id={`dcpgp-${entry.id}`} label={entry.label} color={entry.danger ? "danger" : undefined} action={() => runEntry(entry, channel)} />;
                    case "info":
                        return <Menu.MenuItem key={entry.id} id={`dcpgp-info-${entry.id}`} label={entry.label} disabled />;
                    case "separator":
                        return <Menu.MenuSeparator key={entry.id} />;
                }
            })}
        </Menu.Menu>
    );
}

const ENCRYPTED_TOOLTIP = "Encrypted chat — your next message will be sent encrypted";

export const ChatLockButton: ChatBarButtonFactory = ({ channel, isAnyChat }) => {
    useDcPgpState();
    if (!isAnyChat || !channel) return null;
    const input = menuInput(channel);
    const model = chatButtonModel(input);
    const dot = shouldShowEncryptedDot(input.phase, input.encrypted, input.hookHealthy && !input.visibilityUnknown);
    return (
        <ChatBarButton
            tooltip={dot ? ENCRYPTED_TOOLTIP : model.tooltip}
            onClick={e => ContextMenuApi.openContextMenu(e as any, () => <LockMenu channel={channel} />)}
        >
            {dot ? (
                <span style={{ position: "relative", display: "inline-flex" }}>
                    <LockIcon state={model.icon} />
                    <span aria-hidden="true" style={{ position: "absolute", top: 0, right: 0, width: 6, height: 6, borderRadius: "50%", background: COLORS.ok }} />
                </span>
            ) : <LockIcon state={model.icon} />}
        </ChatBarButton>
    );
};
