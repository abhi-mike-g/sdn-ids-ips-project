#!/bin/bash

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "Starting SDN-NIDPS System"
echo "=========================================="

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down SDN-NIDPS..."
    kill $RYU_PID $DASHBOARD_PID $MONITOR_PID 2>/dev/null || true
    wait $RYU_PID $DASHBOARD_PID $MONITOR_PID 2>/dev/null || true
    echo "System stopped"
}

trap cleanup EXIT

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Starting Suricata monitoring requires root privileges"
   echo "Please run with sudo"
   exit 1
fi

echo "[1/5] Starting Ryu SDN Controller..."
python3 src/controller/sdn_controller.py > logs/controller.log 2>&1 &
RYU_PID=$!
echo "Ryu PID: $RYU_PID"
sleep 3

echo "[2/5] Starting Suricata IDS..."
systemctl restart suricata
echo "Suricata started"
sleep 2

echo "[3/5] Starting Dashboard..."
python3 src/dashboard/app.py > logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "Dashboard PID: $DASHBOARD_PID"
sleep 3

echo "[4/5] Starting Metrics Collector..."
python3 -c "
from src.monitoring.metrics_collector import MetricsCollector
collector = MetricsCollector(interval=5)
collector.start()
import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    collector.stop()
" > logs/metrics.log 2>&1 &
MONITOR_PID=$!
echo "Metrics Collector PID: $MONITOR_PID"

echo "[5/5] Starting Network Topology..."
python3 -c "
from src.network.topology import NetworkTopology
from mininet.log import setLogLevel
setLogLevel('info')
topo = NetworkTopology()
topo.create_simple_topology()
topo.start()
import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    topo.stop()
" > logs/network.log 2>&1 &
TOPO_PID=$!
echo "Network Topology PID: $TOPO_PID"

echo "=========================================="
echo "SDN-NIDPS System Started Successfully!"
echo "=========================================="
echo ""
echo "Services:"
echo "  - Ryu Controller: http://127.0.0.1:6653"
echo "  - Dashboard: http://127.0.0.1:5000"
echo "  - Suricata IDS: /var/log/suricata/eve.json"
echo ""
echo "Log files:"
echo "  - Controller: logs/controller.log"
echo "  - Dashboard: logs/dashboard.log"
echo "  - Metrics: logs/metrics.log"
echo "  - Network: logs/network.log"
echo ""
echo "Press Ctrl+C to stop all services..."
echo ""

# Wait for all processes
wait $RYU_PID $DASHBOARD_PID $MONITOR_PID $TOPO_PID 2>/dev/null || true
