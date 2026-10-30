#!/usr/bin/env bash
# One-command start for macOS / Linux: creates a virtual environment on first run,
# installs dependencies and opens the dashboard on http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}
if [ ! -d .venv ]; then
  echo "Creating virtual environment (.venv)..."
  "$PY" -m venv .venv
  .venv/bin/python -m pip install --upgrade pip >/dev/null
  .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python -m sahakari_guard serve "$@"
