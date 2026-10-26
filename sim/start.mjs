/*
 * DcPgp simulation – entry point (npm run simulate): TypeScript via tsx with the simulation's own tsconfig,
 * then the module hooks, then the run.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { register } from "node:module";
import { fileURLToPath } from "node:url";

import { register as registerTsx } from "tsx/esm/api";

registerTsx({ tsconfig: fileURLToPath(new URL("./tsconfig.json", import.meta.url)) });
register("./loader.mjs", import.meta.url);

await import("./run.ts");
