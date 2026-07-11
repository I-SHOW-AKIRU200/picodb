#!/usr/bin/env sh
# Start PicoDB, loading configuration from .env if present.
# Usage: ./run.sh
set -eu

cd "$(dirname "$0")"

# Load .env (export every assignment) so the server sees PICODB_* vars.
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

if [ ! -x ./target/release/picodb ]; then
  echo "Binary not built yet — running setup first…"
  ./setup.sh
fi

exec ./target/release/picodb
