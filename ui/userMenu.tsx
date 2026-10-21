/*
 * DcPgp – "DcPgp" entry in the user context menu (contact management).
 * Entries come from core/menus.ts (tested).
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { NavContextMenuPatchCallback } from "@api/ContextMenu";
import type { User } from "@vencord/discord-types";
import { ChannelStore, Menu } from "@webpack/common";

import { contactStatus } from "../core/contacts";
import { isKeyExpiringSoon } from "../core/keyLifetime";
import { type UserMenuId, userMenuModel } from "../core/menus";
import { blockContact, openVerifyDialog, removeContactFlow, requestKey, reviewKeyChange, unblockContact } from "../discord/keyExchange";
import { myId, S } from "../discord/state";

function run(id: UserMenuId, userId: string) {
    switch (id) {
        case "request-key":
        case "request-update": return void requestKey(userId);
        case "verify": return void openVerifyDialog(userId);
        case "review-change": return void reviewKeyChange(userId);
        case "block": return void blockContact(userId);
        case "unblock": return void unblockContact(userId);
        // Same flow as the lock menu; the DM with this user (if any) stops being encrypted.
        case "remove": return void removeContactFlow(userId, ChannelStore.getDMFromUserId(userId) ?? null);
    }
}

export const userContextPatch: NavContextMenuPatchCallback = (children, props: { user?: User; }) => {
    const user = props?.user;
    const session = S.session;
    if (!user || user.bot || !session || user.id === myId()) return;

    const entries = userMenuModel(contactStatus(session.data, user.id), {
        outgoingPending: !!session.data.outgoing[user.id],
        hasContact: !!session.data.contacts[user.id],
        keyExpiring: isKeyExpiringSoon(session.data.contacts[user.id]?.keyExpires, Date.now())
    });

    children.push(
        <Menu.MenuSeparator key="dcpgp-separator" />,
        <Menu.MenuItem key="dcpgp-user" id="dcpgp-user" label="DcPgp">
            {entries.map(e => (
                <Menu.MenuItem key={e.id} id={`dcpgp-user-${e.id}`} label={e.label} color={e.danger ? "danger" : undefined} action={() => run(e.id, user.id)} />
            ))}
        </Menu.MenuItem>
    );
};
