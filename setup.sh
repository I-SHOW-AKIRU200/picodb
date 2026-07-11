#!/usr/bin/env sh
# PicoDB one-shot setup: ensure Rust, build, and generate a secure token.
# Usage: ./setup.sh
set -eu

cd "$(dirname "$0")"

echo "==> PicoDB setup"

# 1. Ensure a Rust toolchain is available.
if ! command -v cargo >/dev/null 2>&1; then
  # rustup may be installed but not on PATH yet.
  if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
  fi
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust (cargo) not found."
  printf "Install the official Rust toolchain via rustup now? [y/N] "
  read ans
  case "$ans" in
    y|Y)
      curl -sSf --proto '=https' --tlsv1.2 https://sh.rustup.rs | sh -s -- -y --profile minimal
      . "$HOME/.cargo/env"
      ;;
    *)
      echo "Aborting: Rust is required to build PicoDB. See https://rustup.rs" >&2
      exit 1
      ;;
  esac
fi

# 2. Build the release binary.
echo "==> Building (release)…"
cargo build --release

# 3. Bootstrap a .env with a strong random token (auth ON by default).
if [ ! -f .env ]; then
  TOKEN="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-40)"
  {
    echo "PICODB_TOKEN=$TOKEN"
    echo "PICODB_MAX_BYTES=52428800"
  } > .env
  echo "==> Generated .env with a fresh random PICODB_TOKEN (auth ENABLED)."
else
  echo "==> .env already exists — leaving it untouched."
fi

echo ""
echo "Setup complete. Next:"
echo "  ./run.sh                 # start PicoDB (loads .env)"
echo "  Dashboard : http://127.0.0.1:7121/   (paste the token from .env when prompted)"
echo "  Engine    : 127.0.0.1:7120 (raw binary protocol)"
echo "  Your token is in .env (git-ignored — never commit it)."
