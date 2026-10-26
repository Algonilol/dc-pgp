/*
 * DcPgp simulation – stand-in for "@webpack/common": Discord's stores and actions from sim/world.ts,
 * and inert UI pieces (the simulation drives the plugin's logic, it does not render React).
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { toasts } from "../world";

export {
    ChannelStore, DraftStore, EditMessageStore, FluxDispatcher, MessageActions, MessageStore, UploadAttachmentStore, UserStore
} from "../world";

export const DraftType = { ChannelMessage: 0, ThreadSettings: 1, FirstThreadMessage: 2, ApplicationLauncherCommand: 3, Poll: 4, SlashCommand: 5, ForwardContextMessage: 6 };
export const PermissionsBits = { VIEW_CHANNEL: 1n << 10n, ADMINISTRATOR: 1n << 3n };

export const ChannelActionCreators = { openPrivateChannel: async (_userId: string) => "200000000000000001" };
export const GuildMemberStore = { getNick: () => null, getMember: () => null, isMember: () => false };
export const GuildRoleStore = { getRole: () => undefined };

export const showToast = (o: { text?: string; variant?: string; } | string) => void toasts.push({ kind: "toast", text: typeof o === "string" ? o : String(o?.text ?? "") });

const Inert = () => null;
export const Forms = { FormTitle: Inert, FormText: Inert, FormSection: Inert };
export const TextInput = Inert;
export const Tooltip = Inert;
export const Modal = Inert;
export const Menu = { Menu: Inert, MenuItem: Inert, MenuGroup: Inert, MenuSeparator: Inert, MenuCheckboxItem: Inert };
export const ContextMenuApi = { openContextMenu: () => undefined, closeContextMenu: () => undefined };
export const Parser = { parse: (text: string) => text };
export const openModal = () => "sim-modal";

export const useState = <T,>(initial: T | (() => T)) => [typeof initial === "function" ? (initial as () => T)() : initial, () => undefined] as const;
export const useReducer = <T,>(_reducer: unknown, initial: T) => [initial, () => undefined] as const;
export const useEffect = () => undefined;
export const useLayoutEffect = () => undefined;
export const useStateFromStores = <T,>(_stores: unknown[], get: () => T) => get();
