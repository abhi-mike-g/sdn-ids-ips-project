#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
MODE="${1:---demo}"
if [[ "$MODE" != "--demo" && "$MODE" != "--live" ]]; then
    echo "Usage: $0 [--demo|--live]" >&2; exit 2
fi
if [[ "$MODE" == "--live" ]]; then
    if ! command -v apt-get >/dev/null; then
        echo "Live setup supports Ubuntu 22.04/24.04. Use an Ubuntu VM, or --demo on this host." >&2
        exit 1
    fi
    sudo apt-get update
    sudo apt-get install -y python3-venv python3-dev build-essential openvswitch-switch mininet suricata curl iproute2
fi
PYTHON="${NIDPS_BOOTSTRAP_PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert (3,10) <= sys.version_info[:2] <= (3,12), "Use Python 3.10–3.12 (set NIDPS_BOOTSTRAP_PYTHON)"'
# system-site-packages exposes the distro's Mininet to the venv in live mode.
if [[ "$MODE" == "--live" ]]; then
    "$PYTHON" -m venv --system-site-packages .venv
else
    "$PYTHON" -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip
REQUIREMENTS=requirements.txt
if [[ "$MODE" == "--live" ]]; then REQUIREMENTS=requirements-controller.txt; fi
.venv/bin/python -m pip install -r "$REQUIREMENTS"
mkdir -p logs .run
.venv/bin/python -m models.setup_model
if [[ "$MODE" == "--live" ]]; then
    sudo systemctl start openvswitch-switch
    mkdir -p logs/suricata
    sudo suricata -T -c "$PROJECT_ROOT/config/suricata.yaml" \
        -S "$PROJECT_ROOT/src/detection/rules/custom.rules" -l "$PROJECT_ROOT/logs/suricata"
fi
.venv/bin/python -m src.demo --check
if [[ "$MODE" == "--live" ]]; then
    echo "Setup complete. Start the isolated live lab with: sudo bash scripts/start_system.sh"
else
    echo "Setup complete. Start the offline demo with: bash scripts/run_demo.sh"
fi
