#!/usr/bin/env bash
# PicoDB installer — clone (or update) the repo and run setup.
# Usage:  curl -fsSL https://raw.githubusercontent.com/I-SHOW-AKIRU200/picodb/main/install.sh | bash
set -euo pipefail

REPO_URL="https://github.com/I-SHOW-AKIRU200/picodb.git"
DIR="${PICODB_DIR:-picodb}"

command -v git >/dev/null 2>&1 || { echo "error: git is required" >&2; exit 1; }

if [ -d "$DIR/.git" ]; then
  echo "==> Updating existing checkout in ./$DIR"
  git -C "$DIR" pull --ff-only
else
  echo "==> Cloning PicoDB into ./$DIR"
  git clone --depth 1 "$REPO_URL" "$DIR"
fi

cd "$DIR"

# Run setup with a real terminal for the Rust-install prompt when piped to bash.
if [ -r /dev/tty ]; then
  ./picodb setup < /dev/tty
else
  ./picodb setup
fi

echo ""
echo "PicoDB installed in ./$DIR"
echo "  cd $DIR && ./picodb run     # start the server"
echo "  Dashboard: http://127.0.0.1:7121/"
