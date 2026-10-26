/*
 * DcPgp simulation – stand-in for "@webpack": the few modules the plugin looks up by their properties.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { MessageActions } from "../world";

/** Free accounts: 2,000 characters per message. */
const PremiumUtils = { canUseIncreasedMessageLength: () => false };

export function findByProps(...props: string[]): any {
    if (props.includes("_sendMessage")) return MessageActions;
    if (props.includes("canUseIncreasedMessageLength")) return PremiumUtils;
    return null;
}

export const findByPropsLazy = (...props: string[]) => findByProps(...props) ?? {};

/** Only guild channels use a function found by code (permissions); the simulation is DMs only. */
export const findByCodeLazy = (..._code: unknown[]) => () => {
    throw new Error("Not available in the simulation");
};

export const find = (..._args: unknown[]) => null;
export const findLazy = (..._args: unknown[]) => null;
