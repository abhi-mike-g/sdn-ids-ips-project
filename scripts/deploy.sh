# scripts/deploy.sh
#!/bin/bash

set -e

echo "=== SDN-NIDPS Deployment Script ==="

# 1. Install dependencies
echo "[1/7] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    openvswitch-switch \
    suricata \
    mininet \
    git

# 2. Install Python packages
echo "[2/7] Installing Python dependencies..."
pip3 install -r requirements.txt

# 3. Configure Suricata
echo "[3/7] Configuring Suricata..."
sudo cp config/suricata.yaml /etc/suricata/
sudo suricata-update

# 4. Set up database
echo "[4/7] Initializing database..."
python3 -c "from database.db_manager import init_db; init_db()"

# 5. Build Mininet topology
echo "[5/7] Creating network topology..."
sudo python3 network/topology.py

# 6. Start Ryu controller
echo "[6/7] Starting Ryu controller..."
ryu-manager controller/ryu_controller.py &
RYU_PID=$!

# 7. Start dashboard
echo "[7/7] Starting web dashboard..."
python3 dashboard/app.py &
DASH_PID=$!

echo "=== Deployment Complete ==="
echo "Dashboard: http://localhost:5000"
echo "Controller PID: $RYU_PID"
echo "Dashboard PID: $DASH_PID"
