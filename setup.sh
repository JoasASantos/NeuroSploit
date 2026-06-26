#!/usr/bin/env bash
# NeuroSploit installer — by Joas A Santos & Red Team Leaders
#
#   curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
#
# Builds the v3.5.0 Rust harness and installs the `neurosploit` binary.
# Safe to re-run (idempotent). Honors:
#   NEUROSPLOIT_DIR   install/clone dir   (default: ~/.neurosploit)
#   NEUROSPLOIT_REF   git branch/tag      (default: main)
#   PREFIX            bin install prefix  (default: ~/.local/bin)
set -euo pipefail

REPO="https://github.com/JoasASantos/NeuroSploit.git"
DIR="${NEUROSPLOIT_DIR:-$HOME/.neurosploit}"
REF="${NEUROSPLOIT_REF:-main}"
PREFIX="${PREFIX:-$HOME/.local/bin}"

c()  { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }
say() { c '1;35' "  ▌ $*"; }
ok()  { c '1;32' "  ✓ $*"; }
warn(){ c '1;33' "  ! $*"; }
die() { c '1;31' "  ✗ $*"; exit 1; }

cat <<'BANNER'

   ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗
   ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit installer
   ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   v3.5.2 — Rust harness
   ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos
   ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders
   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
BANNER

# ---- platform detection (Linux / macOS / Windows-via-WSL/MSYS · x64 / arm64) ----
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"
case "$OS_RAW" in
  Linux*)             OS="Linux" ;;
  Darwin*)            OS="macOS" ;;
  MINGW*|MSYS*|CYGWIN*) OS="Windows" ;;
  *)                  OS="$OS_RAW" ;;
esac
case "$ARCH_RAW" in
  x86_64|amd64)   ARCH="x64" ;;
  arm64|aarch64)  ARCH="arm64" ;;
  *)              ARCH="$ARCH_RAW" ;;
esac
say "Platform: $OS / $ARCH"
if [ "$OS" = "Windows" ]; then
  warn "On native Windows, run this in WSL2, Git Bash or MSYS2. (Or build with: cargo build --release)"
fi
if [ "$OS" != "Linux" ] && [ "$OS" != "macOS" ] && [ "$OS" != "Windows" ]; then
  warn "Unrecognized OS '$OS_RAW' — attempting a generic Rust build anyway."
fi

# 1) git
command -v git >/dev/null 2>&1 || die "git is required. Install git and re-run."

# 2) Rust toolchain (rustup)
if ! command -v cargo >/dev/null 2>&1; then
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" || true
fi
if ! command -v cargo >/dev/null 2>&1; then
  say "Rust not found — installing rustup (stable, minimal)…"
  curl --proto '=https' --tlsv1.2 -fsSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
  . "$HOME/.cargo/env"
fi
ok "Rust: $(cargo --version)"

# 3) clone or update
if [ -d "$DIR/.git" ]; then
  say "Updating existing checkout at $DIR…"
  git -C "$DIR" fetch --depth 1 origin "$REF" && git -C "$DIR" checkout -q "$REF" && git -C "$DIR" reset -q --hard "origin/$REF" 2>/dev/null || git -C "$DIR" pull -q
else
  say "Cloning $REPO ($REF) → $DIR…"
  git clone --depth 1 --branch "$REF" "$REPO" "$DIR" 2>/dev/null || git clone --depth 1 "$REPO" "$DIR"
fi

# 4) build
say "Building release binary (first build downloads crates; grab a coffee)…"
( cd "$DIR/neurosploit-rs" && cargo build --release )
BIN="$DIR/neurosploit-rs/target/release/neurosploit"
[ -x "$BIN" ] || die "build did not produce $BIN"
ok "Built: $("$BIN" --version 2>/dev/null || echo neurosploit)"

# 5) install on PATH
mkdir -p "$PREFIX"
ln -sf "$BIN" "$PREFIX/neurosploit"
ok "Installed → $PREFIX/neurosploit"

# 6) optional tooling hints (don't fail if absent)
say "Recommended tools for richer testing (optional):"
for t in curl nmap rustscan ffuf node npx typst; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t present"; else warn "$t missing"; fi
done
echo
warn "Best run on Kali Linux  →  docker run -it --rm kalilinux/kali-rolling"
warn "typst (PDF reports):  cargo install typst-cli   ·   rustscan:  cargo install rustscan"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) warn "Add to PATH:  echo 'export PATH=\"$PREFIX:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
esac

echo
ok "Done. Authenticate a model, then launch:"
echo "      neurosploit                 # interactive session"
echo "      neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v"
echo "      neurosploit --help"
