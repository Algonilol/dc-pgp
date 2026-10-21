/*
 * DcPgp – plugin settings. Only harmless display options live here: Vencord's cloud sync may upload them.
 * Everything sensitive (keys, contacts, which chats are encrypted) is in the encrypted vault.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { OptionType } from "@utils/types";

export const settings = definePluginSettings({
    // quick actions shown in the lock menu
    autoDecrypt: {
        type: OptionType.BOOLEAN,
        description: "Decrypt encrypted messages automatically (can be switched off per chat in the lock menu)",
        default: true
    },

    // technical options
    askUnlockOnStart: {
        type: OptionType.BOOLEAN,
        description: "Ask for the password when Discord starts",
        default: true
    },
    autoLockMinutes: {
        type: OptionType.SLIDER,
        description: "Lock automatically after this many minutes without input on the PC (0 = never)",
        markers: [0, 15, 30, 60, 120, 240],
        default: 60,
        stickToMarkers: true
    },
    lockOnScreenLock: {
        type: OptionType.BOOLEAN,
        description: "Lock when Windows is locked or goes to sleep",
        default: true
    },
    markUnencrypted: {
        type: OptionType.BOOLEAN,
        description: "Mark unencrypted messages in encrypted chats",
        default: true
    },
    blurPlaintext: {
        type: OptionType.BOOLEAN,
        description: "Privacy screen for screen sharing: blur plaintext until the mouse hovers over it",
        default: false
    },
    clipboardClearSeconds: {
        type: OptionType.SLIDER,
        description: "Remove copied plaintext from the clipboard after this many seconds (0 = never)",
        markers: [0, 15, 30, 60, 120, 300],
        default: 60,
        stickToMarkers: true
    },
    showRawCiphertextWhenLocked: {
        type: OptionType.BOOLEAN,
        description: "When locked, show the raw dcpgp/1 block instead of only a placeholder.",
        default: false
    }
});
