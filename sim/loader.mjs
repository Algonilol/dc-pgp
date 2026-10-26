/*
 * DcPgp simulation – Node module hooks: Vencord's and Discord's modules are replaced by the simulation's
 * stand-ins, and text files imported through Vencord's build ("file://…") load as strings.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { readFile } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const mock = name => new URL(`./mocks/${name}`, import.meta.url).href;
/** Own scheme for text imports, so tsx leaves them alone. */
const TEXT = "dcpgp-text:";

const ALIASES = {
    "@webpack/common": mock("webpackCommon.ts"),
    "@webpack": mock("webpack.ts"),
    "@api/MessageEvents": mock("messageEvents.ts"),
    "@api/PluginManager": mock("vencord.ts"),
    "@api/DataStore": mock("vencord.ts"),
    "@api/Settings": mock("vencord.ts"),
    "@api/MessageAccessories": mock("vencord.ts"),
    "@api/ChatButtons": mock("vencord.ts"),
    "@api/ContextMenu": mock("vencord.ts"),
    "@utils/types": mock("vencord.ts"),
    "@utils/Logger": mock("vencord.ts"),
    "@utils/web": mock("vencord.ts"),
    "@utils/clipboard": mock("vencord.ts"),
    "@components/Button": mock("vencord.ts"),
    "@components/Paragraph": mock("vencord.ts"),
    "@vencord/discord-types": mock("vencord.ts"),
    "@vencord/discord-types/enums": mock("vencord.ts")
};

/** Plugin files that would open Discord's UI or need the browser: replaced as a whole. */
const REPLACED = [
    ["/ui/dialogs.tsx", mock("dialogs.ts")],
    ["/ui/keyDialogs.tsx", mock("keyDialogs.ts")],
    ["/discord/argon2.ts", mock("argon2.ts")]
];

export async function resolve(specifier, context, next) {
    if (Object.hasOwn(ALIASES, specifier)) return { url: ALIASES[specifier], shortCircuit: true };
    if (specifier.startsWith("file://") && context.parentURL) {
        // tsx tries a TypeScript extension on files it doesn't know before handing them on: undo that.
        const relative = specifier.slice("file://".length).replace(/(\.(?:txt|js))\.(?:ts|tsx|mts|cts)$/, "$1");
        const path = resolvePath(dirname(fileURLToPath(context.parentURL)), relative);
        return { url: TEXT + encodeURIComponent(pathToFileURL(path).href), shortCircuit: true };
    }
    const result = await next(specifier, context);
    const path = result.url.split("?")[0].replaceAll("\\", "/");
    for (const [suffix, target] of REPLACED)
        if (path.endsWith(suffix)) return { url: target, shortCircuit: true };
    return result;
}

export async function load(url, context, next) {
    if (url.startsWith(TEXT)) {
        const text = await readFile(fileURLToPath(decodeURIComponent(url.slice(TEXT.length))), "utf8");
        return { format: "module", source: `export default ${JSON.stringify(text)};`, shortCircuit: true };
    }
    return next(url, context);
}
