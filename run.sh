#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Error: Python 3 tidak ditemukan." >&2
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "Membuat virtual environment di $ROOT_DIR/venv ..."
    "$PYTHON_BIN" -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate
if ! python -c "import flask" >/dev/null 2>&1; then
    echo "Menginstal dependency ..."
    python -m pip install -r requirements.txt
fi

mkdir -p data
echo "RSA File Encryption tersedia di http://127.0.0.1:${RSA_PORT:-5000}"
exec python app.py
