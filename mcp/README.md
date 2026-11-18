# NeuroSploit MCP Server

> 48 security tools for Claude Code, Cursor, Windsurf, VS Code Copilot and any MCP client.

NeuroSploit exposes its entire pentesting toolkit as an MCP (Model Context Protocol) server.
Ask your AI assistant to "run a pentest on https://target.example.com" and it calls the right tools automatically.

## Quick Install

```bash
# From the repo root:
bash mcp/install.sh

# Or step by step:
bash mcp/install.sh --build      # compile release binary
bash mcp/install.sh --link       # symlink to /usr/local/bin
bash mcp/install.sh --register   # register in Claude Code + Cursor + Windsurf + VS Code
```

## Manual Registration

### Claude Code

```bash
claude mcp add neurosploit -- neurosploit-mcp
```

Or add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "neurosploit": {
      "command": "neurosploit-mcp",
      "args": []
    }
  }
}
```

### Cursor / Windsurf

Add to your MCP settings:

```json
{
  "neurosploit": {
    "command": "neurosploit-mcp",
    "args": []
  }
}
```

### VS Code (Copilot MCP)

Add to `~/.vscode/mcp.json`:

```json
{
  "servers": {
    "neurosploit": {
      "type": "stdio",
      "command": "neurosploit-mcp",
      "args": []
    }
  }
}
```

## Available Tools (48)

### Engagement Tools
| Tool | Description |
|------|-------------|
| `neurosploit_run` | Black-box pentesting against authorized targets |
| `neurosploit_whitebox` | Source code security review |
| `neurosploit_greybox` | Combined source + live app testing |
| `neurosploit_host` | Infrastructure/host scanning (Linux/Windows/AD) |
| `neurosploit_aitest` | AI/LLM red-teaming (OWASP LLM Top 10) |
| `neurosploit_mobile` | Mobile binary analysis (APK/IPA) |
| `neurosploit_container` | Container scanning + SBOM |
| `neurosploit_skills` | Skill/plugin/n8n audit |
| `neurosploit_pr` | GitHub PR security review |
| `neurosploit_internal` | Internal/AD attack graph |

### Results & Reporting
| Tool | Description |
|------|-------------|
| `neurosploit_list_runs` | List completed runs |
| `neurosploit_findings` | Read findings from a run |
| `neurosploit_report` | Read markdown report |
| `neurosploit_rebuild` | Rebuild report from findings |
| `neurosploit_sarif` | Export SARIF 2.1.0 |
| `neurosploit_compliance` | Map to PCI-DSS/HIPAA/SOC2 |
| `neurosploit_graph` | Attack graph visualization |
| `neurosploit_audit` | Verify audit trail |
| `neurosploit_poc` | Re-validate PoCs |
| `neurosploit_traffic` | Export HTTP traffic |
| `neurosploit_assurance` | Assurance bundle |

### C2 Framework
| Tool | Description |
|------|-------------|
| `neurosploit_c2_status` | C2 policy + listeners/sessions |
| `neurosploit_c2_control` | Enable/disable C2 policy |
| `neurosploit_c2_listener` | Listener management |
| `neurosploit_c2_session` | Session management |
| `neurosploit_c2_task` | Task enqueue/wait/get |
| `neurosploit_c2_payload` | Generate payloads |
| `neurosploit_webshell` | WebShell connections |

### Toolbox (200+ Tools)
| Tool | Description |
|------|-------------|
| `neurosploit_tool_list` | List available security tools |
| `neurosploit_tool_info` | Tool details and usage |
| `neurosploit_tool_check` | Check if tool is installed |
| `neurosploit_tool_run` | Execute a security tool |
| `neurosploit_tool_mcp` | Manage MCP tool servers |

### Reactive Engine & Graph
| Tool | Description |
|------|-------------|
| `neurosploit_reactive` | Control reactive engine (hints, chains, status) |
| `neurosploit_knowledge` | Query agent knowledge base |
| `neurosploit_graph_chains` | Find exploitation chain candidates |

### Infrastructure
| Tool | Description |
|------|-------------|
| `neurosploit_neo4j` | Neo4j graph database management |
| `neurosploit_sandbox` | Kali container sandbox management |
| `neurosploit_capability` | Capability token sign/verify |
| `neurosploit_provenance` | Build provenance verification |
| `neurosploit_mcp_profiles` | List MCP tool profiles |
| `neurosploit_config` | Engagement configuration defaults |

### Meta
| Tool | Description |
|------|-------------|
| `neurosploit_agents` | List available agents |
| `neurosploit_models` | List providers and models |
| `neurosploit_import_collection` | Import API collection |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NEUROSPLOIT_BIN` | Override neurosploit binary path |
| `NEUROSPLOIT_INSTALL_DIR` | Override install directory (default: `/usr/local/bin`) |

## Uninstall

```bash
bash mcp/install.sh --uninstall
```

## Protocol

- Transport: stdio (line-delimited JSON-RPC 2.0)
- Protocol version: `2024-11-05`
- Compatible with any MCP client (Claude Code, Cursor, Windsurf, Codex, etc.)
