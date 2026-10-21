/*
 * DcPgp – small helpers around Discord's client stores
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Channel, User } from "@vencord/discord-types";
import { findByCodeLazy, findByPropsLazy } from "@webpack";
import { ChannelActionCreators, ChannelStore, FluxDispatcher, GuildMemberStore, GuildRoleStore, PermissionsBits, UserStore } from "@webpack/common";

import type { ChannelPrefs } from "../core/model";
import { MAX_READERS, planRecipients, type RecipientCandidate, type RecipientPlan } from "../core/send";
import { contactOf, logger, myId, S } from "./state";

const PremiumUtils = findByPropsLazy("canUseIncreasedMessageLength");
/** Discord's own permission calculation, for any member: ({ user, context }) => permission bits. */
const computePermissions: (o: { user: string; context: Channel; }) => unknown = findByCodeLazy("\"string\"==typeof", ".computeLurkerPermissionsAllowList()", "isViewingRoles");

let permissionsUnavailable = false;

/** Whether a member can open a server channel. If Discord's calculation is gone (after an update), everyone counts, as before. */
function canSeeChannel(userId: string, channel: Channel): boolean {
    if (permissionsUnavailable) return true;
    try {
        const permissions = computePermissions({ user: userId, context: channel });
        if (typeof permissions !== "bigint") throw new Error("Unexpected permission value: " + typeof permissions);
        return (permissions & PermissionsBits.VIEW_CHANNEL) === PermissionsBits.VIEW_CHANNEL;
    } catch (e) {
        permissionsUnavailable = true;
        logger.warn("Channel permissions cannot be checked; server messages are encrypted for every contact on the server", e);
        return true;
    }
}

export function userName(user: Pick<User, "globalName" | "username"> | null | undefined, fallback = "Unknown"): string {
    return user?.globalName || user?.username || fallback;
}

export function nameOf(userId: string, guildId?: string | null): string {
    if (guildId) {
        const nick = GuildMemberStore.getNick(guildId, userId);
        if (nick) return nick;
    }
    const contact = contactOf(userId);
    return userName(UserStore.getUser(userId), contact?.name ?? userId);
}

export type ChannelKind = "dm" | "group" | "guild" | "unsupported";

export function channelKind(channel: Channel | null | undefined): ChannelKind {
    if (!channel) return "unsupported";
    if (channel.isDM?.()) return "dm";
    if (channel.isGroupDM?.() || channel.isMultiUserDM?.()) return "group";
    if (channel.getGuildId?.()) return "guild";
    return "unsupported";
}

export function dmPartnerId(channel: Channel): string | null {
    return channel.getRecipientId?.() ?? channel.recipients?.[0] ?? null;
}

/** 2000 or 4000 characters, using Discord's own check for the current account. */
export function maxMessageLength(): number {
    try {
        const user = UserStore.getCurrentUser();
        return PremiumUtils.canUseIncreasedMessageLength(user) ? 4000 : 2000;
    } catch {
        return 2000;
    }
}

const requestedMembers = new Map<string, number>();

/** Asks the gateway for member data of our contacts in a guild (like the client does for message authors). */
export function ensureContactsLoaded(guildId: string) {
    if (!S.session) return;
    const last = requestedMembers.get(guildId) ?? 0;
    if (Date.now() - last < 5 * 60_000) return;
    requestedMembers.set(guildId, Date.now());
    const missing = Object.keys(S.session.data.contacts).filter(id => !GuildMemberStore.getMember(guildId, id));
    if (missing.length) FluxDispatcher.dispatch({ type: "GUILD_MEMBERS_REQUEST", guildIds: [guildId], userIds: missing.slice(0, 500) } as any);
}

function candidate(userId: string, guildId?: string | null): RecipientCandidate {
    return { userId, name: nameOf(userId, guildId), contact: contactOf(userId) };
}

export function defaultTarget(prefs?: ChannelPrefs) {
    return prefs?.target ?? { kind: "all" as const };
}

export interface ChannelPlan extends RecipientPlan {
    kind: ChannelKind;
    /** True when the plan could not be computed (e.g. unsupported channel). */
    unsupported?: boolean;
    capped?: boolean;
}

/** Who can read a message encrypted in this channel, and who cannot (and why). */
export function planForChannel(channel: Channel | null | undefined): ChannelPlan {
    const kind = channelKind(channel);
    const me = myId();
    if (!channel || !S.session || !me || kind === "unsupported") return { kind, readers: [], missing: [], unsupported: true };

    let candidates: RecipientCandidate[] = [];
    if (kind === "dm") {
        const partner = dmPartnerId(channel);
        if (partner) candidates = [candidate(partner)];
    } else if (kind === "group") {
        candidates = (channel.recipients ?? []).map(id => candidate(id));
    } else {
        const guildId = channel.getGuildId();
        ensureContactsLoaded(guildId);
        const target = defaultTarget(S.session.data.channels[channel.id]);
        if (target.kind === "members") {
            candidates = target.userIds.map(id => candidate(id, guildId));
        } else if (target.kind === "role") {
            candidates = Object.keys(S.session.data.contacts)
                .filter(id => GuildMemberStore.getMember(guildId, id)?.roles?.includes(target.roleId) && canSeeChannel(id, channel))
                .map(id => candidate(id, guildId));
        } else {
            // Only contacts who can open this channel: a private channel is not encrypted for the whole server.
            candidates = Object.keys(S.session.data.contacts)
                .filter(id => GuildMemberStore.isMember(guildId, id) && canSeeChannel(id, channel))
                .map(id => candidate(id, guildId));
        }
    }

    const plan = planRecipients(candidates, S.session.data.blocked, me);
    const capped = plan.readers.length > MAX_READERS;
    if (capped) plan.readers = plan.readers.slice(0, MAX_READERS);
    return { ...plan, kind, capped };
}

export function roleName(guildId: string, roleId: string): string {
    try {
        return GuildRoleStore.getRole(guildId, roleId)?.name ?? "Role";
    } catch {
        return "Role";
    }
}

/** Opens (and if needed creates) the DM with a user and returns its channel id. */
export async function ensureDmChannel(userId: string): Promise<string> {
    const existing = ChannelStore.getDMFromUserId(userId);
    if (existing) return existing;
    const result = await ChannelActionCreators.openPrivateChannel(userId);
    if (typeof result === "string") return result;
    for (let i = 0; i < 50; i++) {
        const id = ChannelStore.getDMFromUserId(userId);
        if (id) return id;
        await new Promise(r => setTimeout(r, 100));
    }
    throw new Error("Could not open the direct message");
}
