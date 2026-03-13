#!/usr/bin/env node
// Auto-configure Agent Passport MCP for Claude Desktop, Cursor, Windsurf
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";

const LOCAL_CONFIG = {
  command: "npx",
  args: ["agent-passport-system-mcp"],
};

const REMOTE_CONFIG = {
  type: "sse",
  url: "https://mcp.aeoess.com/sse",
};

interface McpConfig {
  mcpServers?: Record<string, unknown>;
  [key: string]: unknown;
}

function getConfigPaths(): { name: string; path: string }[] {
  const home = homedir();
  const paths: { name: string; path: string }[] = [];

  if (platform() === "darwin") {
    paths.push({
      name: "Claude Desktop",
      path: join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    });
    paths.push({
      name: "Cursor",
      path: join(home, ".cursor", "mcp.json"),
    });
  } else if (platform() === "win32") {
    const appdata = process.env.APPDATA || join(home, "AppData", "Roaming");
    paths.push({
      name: "Claude Desktop",
      path: join(appdata, "Claude", "claude_desktop_config.json"),
    });
    paths.push({
      name: "Cursor",
      path: join(home, ".cursor", "mcp.json"),
    });
  } else {
    paths.push({
      name: "Claude Desktop",
      path: join(home, ".config", "Claude", "claude_desktop_config.json"),
    });
    paths.push({
      name: "Cursor",
      path: join(home, ".cursor", "mcp.json"),
    });
  }
  return paths;
}

function setup() {
  const useRemote = process.argv.includes("--remote");
  const serverConfig = useRemote ? REMOTE_CONFIG : LOCAL_CONFIG;
  const mode = useRemote ? "remote (SSE)" : "local (npx)";

  console.log(`\n🔑 Agent Passport MCP Setup (${mode})\n`);

  const configs = getConfigPaths();
  let configured = 0;

  for (const { name, path } of configs) {
    try {
      let config: McpConfig = {};

      if (existsSync(path)) {
        const raw = readFileSync(path, "utf-8");
        config = JSON.parse(raw);
      } else {
        const dir = path.substring(0, path.lastIndexOf("/"));
        mkdirSync(dir, { recursive: true });
      }

      if (!config.mcpServers) config.mcpServers = {};

      if (config.mcpServers["agent-passport"]) {
        console.log(`  ✓ ${name} — already configured`);
        configured++;
        continue;
      }

      config.mcpServers["agent-passport"] = serverConfig;
      writeFileSync(path, JSON.stringify(config, null, 2) + "\n");
      console.log(`  ✓ ${name} — configured at ${path}`);
      configured++;
    } catch {
      // Config dir doesn't exist = app not installed, skip
    }
  }

  if (configured === 0) {
    console.log("  No supported MCP clients found.");
    console.log("  Manual setup: add this to your MCP config:\n");
    console.log(JSON.stringify({ mcpServers: { "agent-passport": serverConfig } }, null, 2));
  } else {
    console.log(`\n  Restart your AI client to activate Agent Passport (61 tools).`);
    console.log(`  Then say: "Create an agent identity" or "Delegate authority"\n`);
    if (!useRemote) {
      console.log(`  Tip: Use --remote for zero-install SSE mode: npx agent-passport-system-mcp setup --remote\n`);
    }
  }
}

setup();
