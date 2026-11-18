#!/usr/bin/env node
// Post-install: tell the user how to register the MCP server.
'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');

const wrapper = path.resolve(__dirname, 'neurosploit-mcp');
const home = os.homedir();

// Claude Code config path
const claudeSettings = path.join(home, '.claude', 'settings.json');
const cursorSettings = path.join(home, '.cursor', 'mcp.json');

console.log(`
╔══════════════════════════════════════════════════════════════╗
║  NeuroSploit MCP Server installed                            ║
╚══════════════════════════════════════════════════════════════╝

  Binary wrapper: ${wrapper}

  Register in your MCP client:

  ┌─ Claude Code ─────────────────────────────────────────────┐
  │  claude mcp add neurosploit -- ${wrapper}                  │
  │                                                            │
  │  Or add to ~/.claude/settings.json:                        │
  │  "mcpServers": {                                           │
  │    "neurosploit": {                                        │
  │      "command": "${wrapper}",                              │
  │      "args": []                                            │
  │    }                                                       │
  │  }                                                         │
  └────────────────────────────────────────────────────────────┘

  ┌─ Cursor / Windsurf ───────────────────────────────────────┐
  │  Add to MCP settings:                                      │
  │  {                                                         │
  │    "neurosploit": {                                        │
  │      "command": "${wrapper}",                              │
  │      "args": []                                            │
  │    }                                                       │
  │  }                                                         │
  └────────────────────────────────────────────────────────────┘

  Or run: neurosploit-mcp --install to auto-configure.
`);
