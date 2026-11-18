#!/usr/bin/env bash
# install.sh — Build neurosploit, install globally, register as MCP server.
# Usage:
#   bash install.sh              # full install (build + link + register)
#   bash install.sh --register   # register only (binary already built)
#   bash install.sh --uninstall  # remove MCP registration
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_NAME="neurosploit"
MCP_NAME="neurosploit"
INSTALL_DIR="${NEUROSPLOIT_INSTALL_DIR:-/usr/local/bin}"
WRAPPER="$(cd "$(dirname "$0")" && pwd)/bin/neurosploit-mcp"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

info()  { echo -e "${CYAN}▸${RESET} $*"; }
ok()    { echo -e "${GREEN}✓${RESET} $*"; }
fail()  { echo -e "${RED}✗${RESET} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

claude_settings() {
  local home="${HOME:-$(eval echo ~)}"
  echo "$home/.claude/settings.json"
}

ensure_json_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    mkdir -p "$(dirname "$f")"
    echo '{}' > "$f"
  fi
}

# Register MCP server in a JSON config file using node (available everywhere npm is).
register_mcp() {
  local config_file="$1"
  local server_name="$2"
  local command="$3"

  ensure_json_file "$config_file"

  node -e "
    const fs = require('fs');
    const f = process.argv[1];
    const name = process.argv[2];
    const cmd = process.argv[3];
    let cfg = {};
    try { cfg = JSON.parse(fs.readFileSync(f, 'utf8')); } catch {}
    if (!cfg.mcpServers) cfg.mcpServers = {};
    cfg.mcpServers[name] = { command: cmd, args: [] };
    fs.writeFileSync(f, JSON.stringify(cfg, null, 2) + '\n');
  " "$config_file" "$server_name" "$command"
}

unregister_mcp() {
  local config_file="$1"
  local server_name="$2"
  [[ ! -f "$config_file" ]] && return 0

  node -e "
    const fs = require('fs');
    const f = process.argv[1];
    const name = process.argv[2];
    let cfg = {};
    try { cfg = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return; }
    if (cfg.mcpServers) delete cfg.mcpServers[name];
    fs.writeFileSync(f, JSON.stringify(cfg, null, 2) + '\n');
  " "$config_file" "$server_name"
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

do_build() {
  info "Building neurosploit (release)..."
  if [[ -f "$REPO_ROOT/neurosploit-rs/Cargo.toml" ]]; then
    (cd "$REPO_ROOT/neurosploit-rs" && cargo build --release 2>&1 | tail -3)
    ok "Build complete"
  else
    fail "Cargo.toml not found at $REPO_ROOT/neurosploit-rs/"
  fi
}

do_link() {
  local src="$REPO_ROOT/neurosploit-rs/target/release/$BIN_NAME"
  [[ -x "$src" ]] || fail "Binary not found: $src — run build first"

  info "Linking $BIN_NAME to $INSTALL_DIR/"
  if [[ -w "$INSTALL_DIR" ]]; then
    ln -sf "$src" "$INSTALL_DIR/$BIN_NAME"
  else
    sudo ln -sf "$src" "$INSTALL_DIR/$BIN_NAME"
  fi
  ok "$BIN_NAME linked to $INSTALL_DIR/$BIN_NAME"

  # Also link the MCP wrapper
  local mcp_wrapper="$REPO_ROOT/mcp/bin/neurosploit-mcp"
  if [[ -x "$mcp_wrapper" ]]; then
    if [[ -w "$INSTALL_DIR" ]]; then
      ln -sf "$mcp_wrapper" "$INSTALL_DIR/neurosploit-mcp"
    else
      sudo ln -sf "$mcp_wrapper" "$INSTALL_DIR/neurosploit-mcp"
    fi
    ok "neurosploit-mcp linked to $INSTALL_DIR/neurosploit-mcp"
  fi
}

do_register() {
  local home="${HOME:-$(eval echo ~)}"

  # Claude Code
  local claude_cfg
  claude_cfg="$(claude_settings)"
  info "Registering MCP server in Claude Code ($claude_cfg)"
  register_mcp "$claude_cfg" "$MCP_NAME" "neurosploit-mcp"
  ok "Claude Code: registered"

  # Claude Code project-level (optional, for this repo)
  local project_cfg="$REPO_ROOT/.claude/settings.json"
  if [[ -d "$REPO_ROOT/.claude" ]]; then
    register_mcp "$project_cfg" "$MCP_NAME" "neurosploit-mcp"
    ok "Project .claude/settings.json: registered"
  fi

  # Cursor
  local cursor_cfg="$home/.cursor/mcp.json"
  if [[ -d "$home/.cursor" ]]; then
    ensure_json_file "$cursor_cfg"
    register_mcp "$cursor_cfg" "$MCP_NAME" "neurosploit-mcp"
    ok "Cursor: registered ($cursor_cfg)"
  fi

  # Windsurf
  local windsurf_cfg="$home/.windsurf/mcp.json"
  if [[ -d "$home/.windsurf" ]]; then
    ensure_json_file "$windsurf_cfg"
    register_mcp "$windsurf_cfg" "$MCP_NAME" "neurosploit-mcp"
    ok "Windsurf: registered ($windsurf_cfg)"
  fi

  # VS Code (Copilot MCP)
  local vscode_cfg="$home/.vscode/mcp.json"
  if [[ -d "$home/.vscode" ]]; then
    ensure_json_file "$vscode_cfg"
    register_mcp "$vscode_cfg" "$MCP_NAME" "neurosploit-mcp"
    ok "VS Code: registered ($vscode_cfg)"
  fi

  echo ""
  ok "MCP server registered globally. 48 security tools available."
  echo ""
  echo -e "  ${DIM}Tools: neurosploit_run, neurosploit_whitebox, neurosploit_greybox,"
  echo -e "  neurosploit_host, neurosploit_aitest, neurosploit_mobile,"
  echo -e "  neurosploit_container, neurosploit_skills, neurosploit_pr,"
  echo -e "  neurosploit_c2_*, neurosploit_tool_*, neurosploit_neo4j,"
  echo -e "  neurosploit_reactive, neurosploit_knowledge, ...${RESET}"
  echo ""
  echo -e "  Test: ${CYAN}claude mcp list${RESET} — should show 'neurosploit'"
  echo -e "  Then: ${CYAN}\"run a pentest on https://target.example.com\"${RESET}"
}

do_uninstall() {
  local home="${HOME:-$(eval echo ~)}"
  info "Removing MCP registrations..."
  unregister_mcp "$(claude_settings)" "$MCP_NAME"
  unregister_mcp "$home/.cursor/mcp.json" "$MCP_NAME" 2>/dev/null || true
  unregister_mcp "$home/.windsurf/mcp.json" "$MCP_NAME" 2>/dev/null || true
  unregister_mcp "$home/.vscode/mcp.json" "$MCP_NAME" 2>/dev/null || true
  rm -f "$INSTALL_DIR/$BIN_NAME" "$INSTALL_DIR/neurosploit-mcp" 2>/dev/null || true
  ok "MCP server unregistered and binaries removed"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "${1:-full}" in
  --register|-r)   do_register ;;
  --uninstall|-u)  do_uninstall ;;
  --build|-b)      do_build ;;
  --link|-l)       do_link ;;
  full|--full)
    do_build
    do_link
    do_register
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║  NeuroSploit MCP Server — installed globally     ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${RESET}"
    ;;
  *)
    echo "Usage: install.sh [full|--register|--uninstall|--build|--link]"
    exit 1
    ;;
esac
