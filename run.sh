#!/usr/bin/env bash
# Local setup + launch. Works on Linux/macOS AND Windows (Git Bash / MSYS).
#
#   ./run.sh setup     install Python + Node deps and build the UI
#   ./run.sh backend   production mode (no demo helpers) on http://127.0.0.1:8765
#   ./run.sh demo      demo mode: seed/reset/tamper helpers, leak simulator, robustness lab
#   ./run.sh desktop   Electron app (add DEMO=1 for demo mode)
#   ./run.sh dev       backend (demo, --reload) + Vite dev server on :5173
#   ./run.sh test      pytest suite
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

# Windows venvs use Scripts/, Linux/macOS use bin/
if [ -x "$ROOT/.venv/Scripts/python.exe" ]; then
  PY="$ROOT/.venv/Scripts/python.exe"
elif [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$ROOT/.venv/Scripts/python"
fi
UVICORN=("$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8765)

setup() {
  if ! "$PY" --version >/dev/null 2>&1; then
    python3 -m venv "$ROOT/.venv"
    # re-resolve after creating the venv
    if [ -x "$ROOT/.venv/Scripts/python.exe" ]; then PY="$ROOT/.venv/Scripts/python.exe"
    else PY="$ROOT/.venv/bin/python"; fi
  fi
  "$PY" -m pip install -q -r "$ROOT/requirements.txt"
  (cd "$ROOT/frontend" && npm install --no-audit --no-fund && npm run build)
}

case "${1:-demo}" in
  setup)   setup ;;
  backend) cd "$ROOT/backend" && exec "${UVICORN[@]}" ;;
  demo)    cd "$ROOT/backend" && SIH_DEMO=1 exec "${UVICORN[@]}" ;;
  desktop) [ -d "$ROOT/frontend/dist" ] || setup
           cd "$ROOT/frontend" && SIH_DEMO="${DEMO:-}" exec npx electron . ;;
  dev)     (cd "$ROOT/backend" && SIH_DEMO=1 SIH_DEV=1 "${UVICORN[@]}" --reload) &
           cd "$ROOT/frontend" && exec npm run dev ;;
  test)    exec "$PY" -m pytest "$ROOT/backend/tests" -q ;;
  *) echo "usage: $0 [setup|backend|demo|desktop|dev|test]"; exit 1 ;;
esac
