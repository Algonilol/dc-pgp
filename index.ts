/*
 * DcPgp – Vencord userplugin entry: end-to-end PGP encryption for Discord messages (dcpgp/1)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { addMessageAccessory, removeMessageAccessory } from "@api/MessageAccessories";
import definePlugin from "@utils/types";
import { UserStore } from "@webpack/common";

import { startAutolock, stopAutolock } from "./discord/autolock";
import { handleMessageCreate, handleMessageUpdate, startDecryption, stopDecryption } from "./discord/decrypt";
import { startHiding, stopHiding } from "./discord/hide";
import { onMessageCreate, startKeyExchange, stopKeyExchange } from "./discord/keyExchange";
import { installSendProtection, uninstallSendProtection } from "./discord/sendHooks";
import { forgetSession, loadForUser, logger, S } from "./discord/state";
import { settings } from "./settings";
import { ChatLockButton } from "./ui/ChatLockButton";
import { LockIcon } from "./ui/icons";
import { renderMessageAccessory } from "./ui/MessageView";
import { SettingsPanel } from "./ui/SettingsPanel";
import { openUnlockModal } from "./ui/UnlockModal";
import { userContextPatch } from "./ui/userMenu";

const ACCESSORY_ID = "dcpgp-message";

let unlockPrompted = false;

function protect() {
    for (const problem of installSendProtection()) logger.warn(problem);
}

function maybePromptUnlock() {
    if (unlockPrompted || S.phase !== "locked" || !settings.store.askUnlockOnStart) return;
    unlockPrompted = true;
    openUnlockModal();
}

function loadCurrentUser() {
    const user = UserStore.getCurrentUser();
    if (!user) return;
    loadForUser(user.id)
        .then(maybePromptUnlock)
        .catch(e => logger.error("Could not load the vault", e));
}

function resetState() {
    forgetSession();
    unlockPrompted = false;
    S.userId = null;
    S.file = null;
    S.phase = "loading";
    S.emit();
}

export default definePlugin({
    name: "DcPgp",
    description: "End-to-End PGP Encryption for Discord",
    authors: [{ name: "Algoni", id: 0n }],
    // Whoever builds Vencord with this plugin wants it: no extra trip to the plugin list after installing.
    enabledByDefault: true,
    dependencies: ["MessageEventsAPI", "MessageAccessoriesAPI"],
    settings,
    settingsAboutComponent: SettingsPanel,

    chatBarButton: {
        icon: LockIcon,
        render: ChatLockButton
    },

    contextMenus: {
        "user-context": userContextPatch
    },

    flux: {
        CONNECTION_OPEN() {
            protect();
            loadCurrentUser();
        },
        LOGOUT() {
            resetState();
        },
        MESSAGE_CREATE({ message, optimistic }: { message: any; optimistic?: boolean; }) {
            if (!message) return;
            handleMessageCreate(message, !!optimistic);
            if (!optimistic) onMessageCreate(message);
        },
        MESSAGE_UPDATE({ message }: { message: any; }) {
            if (message) handleMessageUpdate(message);
        }
    },

    start() {
        protect();
        startHiding();
        startDecryption();
        // Position 0: right below the hidden PGP block, above attachments and embeds.
        addMessageAccessory(ACCESSORY_ID, renderMessageAccessory, 0);
        startKeyExchange();
        startAutolock();
        loadCurrentUser();
    },

    stop() {
        stopAutolock();
        uninstallSendProtection();
        removeMessageAccessory(ACCESSORY_ID);
        stopDecryption();
        stopHiding();
        stopKeyExchange();
        resetState();
    }
});
