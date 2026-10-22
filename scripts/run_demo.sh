#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
PYTHON="${NIDPS_PYTHON:-$PROJECT_ROOT/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
    echo "Run bash scripts/setup_environment.sh --demo first, or set NIDPS_PYTHON." >&2
    exit 1
fi
if [[ "${1:-}" == "--live" ]]; then
    shift
    exec "$PYTHON" -m src.network.demo "$@"
fi
exec "$PYTHON" -m src.demo "$@"
