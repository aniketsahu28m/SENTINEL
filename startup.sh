#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

if [ ! -d "$BACKEND_DIR/.venv" ]; then
  echo "Missing backend virtual environment at backend/.venv"
  echo "Create it with: cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

(
  cd "$BACKEND_DIR"
  source .venv/bin/activate
  python scanner.py
) &
BACKEND_PID=$!

(
  cd "$FRONTEND_DIR"
  npm run dev -- --host
) &
FRONTEND_PID=$!

cleanup() {
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

sleep 3
if command -v open >/dev/null 2>&1; then
  open http://localhost:5173
fi

wait "$BACKEND_PID" "$FRONTEND_PID"