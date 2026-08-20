#!/usr/bin/env node
// Generates tools-manifest.json from the RUNTIME tool registry.
//
// Loads the built server module and reads REGISTERED_TOOL_NAMES, which every call
// through the registerTool wrapper appends to. It does NOT scrape
// `server.registerTool(` out of source text: that primitive silently returned zero
// for a downstream consumer once the registration API was renamed, and a manifest
// built that way would repeat the failure one layer over.
//
// createSandboxServer() is called immediately after import. That is the module's own
// documented mechanism for suppressing startup: main() is deferred behind a
// setTimeout precisely so this flag can be set first, so the server never connects a
// transport here.
//
// The registry is populated BEFORE the wrapper's profile filter, so this output is a
// property of the source and not of APS_PROFILE. Verified by generating under two
// profiles and comparing.

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const OUT = fileURLToPath(new URL("../tools-manifest.json", import.meta.url));
const MOD = new URL("../build/index.js", import.meta.url);

const mod = await import(MOD.href);
if (typeof mod.createSandboxServer === "function") mod.createSandboxServer();

const tools = mod.REGISTERED_TOOL_NAMES;
if (!Array.isArray(tools) || tools.length === 0) {
  console.error("generate-manifest: REGISTERED_TOOL_NAMES is empty or not exported.");
  console.error("  The registry is the source of truth for the tool inventory; refusing");
  console.error("  to write a manifest that would understate it.");
  process.exit(1);
}

const dupes = tools.filter((n, i) => tools.indexOf(n) !== i);
if (dupes.length) {
  console.error(`generate-manifest: duplicate tool names registered: ${[...new Set(dupes)].join(", ")}`);
  process.exit(1);
}

const manifest = {
  generated_by: "scripts/generate-manifest.mjs from src/index.ts REGISTERED_TOOL_NAMES. Generated file, do not hand-edit.",
  count: tools.length,
  tools: [...tools].sort(),
};

writeFileSync(OUT, JSON.stringify(manifest, null, 2) + "\n");
console.log(`tools-manifest.json written: ${manifest.count} tools`);
process.exit(0);
