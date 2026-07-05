#!/usr/bin/env bash
# NeuroSploit installer — by Joas A Santos & Red Team Leaders
#
#   curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
#
# Downloads the prebuilt `neurosploit` binary + agent library, installs them, and
# sets up PATH + NEUROSPLOIT_BASE so you can run `neurosploit` from ANY folder —
# no need to cd into the repo. Falls back to building from source if no prebuilt
# asset fits (or NEUROSPLOIT_BUILD=1). Safe to re-run (idempotent). Honors:
#   NEUROSPLOIT_DIR   install dir         (default: ~/.neurosploit-app)
#   NEUROSPLOIT_REF   release tag/branch  (default: latest release)
#   NEUROSPLOIT_BUILD 1 = build from source instead of downloading
#   PREFIX            bin symlink dir     (default: ~/.local/bin)
set -euo pipefail

REPO_SLUG="JoasASantos/NeuroSploit"
REPO="https://github.com/${REPO_SLUG}.git"
DIR="${NEUROSPLOIT_DIR:-$HOME/.neurosploit-app}"
PREFIX="${PREFIX:-$HOME/.local/bin}"

c()  { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }
say(){ c '1;35' "  ▌ $*"; }
ok() { c '1;32' "  ✓ $*"; }
warn(){ c '1;33' "  ! $*"; }
die(){ c '1;31' "  ✗ $*"; exit 1; }

cat <<'BANNER'

   ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗
   ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit installer
   ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   v3.5.5 — Rust harness
   ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos
   ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders
   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
BANNER

# ---- platform detection (Linux / macOS / Windows-WSL · x64 / arm64) ----
OS_RAW="$(uname -s)"; ARCH_RAW="$(uname -m)"
case "$OS_RAW" in
  Linux*)  OS="linux" ;;
  Darwin*) OS="macos" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *) OS="$OS_RAW" ;;
esac
case "$ARCH_RAW" in
  x86_64|amd64)  ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$ARCH_RAW" ;;
esac
PLAT="${OS}-${ARCH}"
say "Platform: $PLAT"
[ "$OS" = "windows" ] && warn "Native Windows: prefer install.ps1 (PowerShell). This path works under WSL2/Git Bash."

dl() { # dl <url> <out>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else return 1; fi
}

# ---- resolve the release tag (latest, unless pinned) ----
REF="${NEUROSPLOIT_REF:-}"
if [ -z "$REF" ]; then
  REF="$(dl "https://api.github.com/repos/${REPO_SLUG}/releases/latest" /dev/stdout 2>/dev/null \
         | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/' || true)"
fi
[ -z "$REF" ] && REF="v3.5.5"
say "Release: $REF"

installed=0
if [ "${NEUROSPLOIT_BUILD:-0}" != "1" ] && [ "$OS" != "windows" ]; then
  # ---- try the prebuilt asset (no Rust needed) ----
  ASSET="neurosploit-${REF}-${PLAT}.tar.gz"
  URL="https://github.com/${REPO_SLUG}/releases/download/${REF}/${ASSET}"
  TMP="$(mktemp -d)"
  say "Downloading prebuilt binary: $ASSET"
  if dl "$URL" "$TMP/a.tar.gz"; then
    mkdir -p "$DIR"
    tar -xzf "$TMP/a.tar.gz" -C "$TMP" 2>/dev/null || die "download was not a valid archive"
    SRC="$(find "$TMP" -maxdepth 2 -name neurosploit -type f | head -1)"
    [ -n "$SRC" ] || die "extracted archive has no neurosploit binary"
    SRCDIR="$(dirname "$SRC")"
    rm -rf "$DIR/neurosploit" "$DIR/agents_md"
    cp "$SRCDIR/neurosploit" "$DIR/neurosploit"
    cp -R "$SRCDIR/agents_md" "$DIR/agents_md"
    chmod +x "$DIR/neurosploit"
    rm -rf "$TMP"
    installed=1
    ok "Downloaded & unpacked → $DIR"
  else
    rm -rf "$TMP"
    warn "No prebuilt asset for $PLAT ($REF) — building from source instead."
  fi
fi

if [ "$installed" != "1" ]; then
  # ---- build from source (needs git + Rust) ----
  command -v git >/dev/null 2>&1 || die "git is required to build from source."
  if ! command -v cargo >/dev/null 2>&1; then [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" || true; fi
  if ! command -v cargo >/dev/null 2>&1; then
    say "Rust not found — installing rustup (stable, minimal)…"
    curl --proto '=https' --tlsv1.2 -fsSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    . "$HOME/.cargo/env"
  fi
  ok "Rust: $(cargo --version)"
  SRC_CO="$DIR/src"
  if [ -d "$SRC_CO/.git" ]; then
    say "Updating checkout…"; git -C "$SRC_CO" fetch --depth 1 origin "$REF" 2>/dev/null && git -C "$SRC_CO" checkout -q FETCH_HEAD 2>/dev/null || git -C "$SRC_CO" pull -q || true
  else
    say "Cloning $REPO ($REF)…"; git clone --depth 1 --branch "$REF" "$REPO" "$SRC_CO" 2>/dev/null || git clone --depth 1 "$REPO" "$SRC_CO"
  fi
  say "Building release binary (first build downloads crates)…"
  ( cd "$SRC_CO/neurosploit-rs" && cargo build --release )
  cp "$SRC_CO/neurosploit-rs/target/release/neurosploit" "$DIR/neurosploit"
  rm -rf "$DIR/agents_md"; cp -R "$SRC_CO/agents_md" "$DIR/agents_md"
  chmod +x "$DIR/neurosploit"
  ok "Built → $DIR"
fi

# ---- install on PATH ----
mkdir -p "$PREFIX"
ln -sf "$DIR/neurosploit" "$PREFIX/neurosploit"
ok "Linked → $PREFIX/neurosploit"
ok "Version: $(NEUROSPLOIT_BASE="$DIR" "$DIR/neurosploit" --version 2>/dev/null || echo neurosploit)"

# ---- persist env (PATH + NEUROSPLOIT_BASE) so it runs from any folder ----
persist() { # append an idempotent block to a shell rc that exists
  local rc="$1"; [ -e "$rc" ] || return 0
  grep -q 'NEUROSPLOIT_BASE' "$rc" 2>/dev/null && return 0
  { echo ''; echo '# NeuroSploit (added by setup.sh)'
    echo "export NEUROSPLOIT_BASE=\"$DIR\""
    echo "export PATH=\"$PREFIX:\$PATH\""; } >> "$rc"
  ok "Configured $rc"
}
SHELL_NAME="$(basename "${SHELL:-bash}")"
case "$SHELL_NAME" in
  zsh)  touch "$HOME/.zshrc"; persist "$HOME/.zshrc" ;;
  bash) touch "$HOME/.bashrc"; persist "$HOME/.bashrc"; persist "$HOME/.bash_profile" ;;
  *)    touch "$HOME/.profile"; persist "$HOME/.profile" ;;
esac
if [ -d "$HOME/.config/fish" ]; then
  FCONF="$HOME/.config/fish/config.fish"
  if ! grep -q 'NEUROSPLOIT_BASE' "$FCONF" 2>/dev/null; then
    { echo ''; echo '# NeuroSploit'; echo "set -gx NEUROSPLOIT_BASE \"$DIR\""; echo "set -gx PATH \"$PREFIX\" \$PATH"; } >> "$FCONF"
    ok "Configured $FCONF"
  fi
fi

# ---- optional tooling hints ----
say "Recommended tools (optional): curl nmap rustscan ffuf node npx typst"
for t in curl nmap rustscan ffuf node npx typst; do
  command -v "$t" >/dev/null 2>&1 && ok "$t present" || warn "$t missing"
done

echo
ok "Installed. Open a NEW terminal — or run now with:"
echo "      export NEUROSPLOIT_BASE=\"$DIR\"; export PATH=\"$PREFIX:\$PATH\""
echo "  then, from ANY folder:"
echo "      neurosploit                 # interactive session"
echo "      neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v"
echo "      neurosploit --help"
echo
warn "Update later: just re-run this script.   Best runtime: Kali (docker run -it kalilinux/kali-rolling)."
