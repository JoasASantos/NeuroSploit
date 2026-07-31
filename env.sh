# NeuroSploit environment — source this to use `neurosploit` in the CURRENT shell
# without reinstalling or opening a new terminal:
#
#     source env.sh            # from a repo checkout or an install dir
#     source ~/.neurosploit-app/env.sh
#
# It exports:
#   NEUROSPLOIT_BASE  the app/agents base dir (agents_md lives here)
#   NEUROSPLOIT       full path to the neurosploit binary
#   PATH              prepended with the binary's dir so `neurosploit` resolves
#
# Honors NEUROSPLOIT_DIR to point at a custom install dir. Safe to source twice.

# Resolve where this script lives (works when sourced from bash or zsh).
if [ -n "${BASH_SOURCE:-}" ]; then _ns_self="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_VERSION:-}" ]; then _ns_self="${(%):-%N}"
else _ns_self="$0"; fi
_ns_here="$(cd "$(dirname "$_ns_self")" >/dev/null 2>&1 && pwd)"

# Pick the base dir: explicit override → this script's dir → default install dir.
_ns_base="${NEUROSPLOIT_DIR:-$_ns_here}"

# Find the binary: alongside the base, in a repo release build, or on PATH.
_ns_bin=""
for _c in \
  "$_ns_base/neurosploit" \
  "$_ns_here/neurosploit" \
  "$_ns_here/neurosploit-rs/target/release/neurosploit" \
  "$_ns_here/target/release/neurosploit" \
  "$HOME/.neurosploit-app/neurosploit"
do
  if [ -x "$_c" ]; then _ns_bin="$_c"; break; fi
done
if [ -z "$_ns_bin" ] && command -v neurosploit >/dev/null 2>&1; then
  _ns_bin="$(command -v neurosploit)"
fi

if [ -z "$_ns_bin" ]; then
  echo "neurosploit binary not found — run setup.sh (or set NEUROSPLOIT_DIR) first." >&2
else
  # agents_md sits next to the binary unless the base already has it.
  if [ -d "$_ns_base/agents_md" ]; then :; else _ns_base="$(dirname "$_ns_bin")"; fi
  export NEUROSPLOIT_BASE="$_ns_base"
  export NEUROSPLOIT="$_ns_bin"
  case ":$PATH:" in
    *":$(dirname "$_ns_bin"):"*) : ;;                 # already on PATH
    *) export PATH="$(dirname "$_ns_bin"):$PATH" ;;
  esac
  echo "NeuroSploit ready — NEUROSPLOIT=$NEUROSPLOIT · NEUROSPLOIT_BASE=$NEUROSPLOIT_BASE"
fi

unset _ns_self _ns_here _ns_base _ns_bin _c
