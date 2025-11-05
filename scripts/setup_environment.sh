#!/bin/bash

set -e

echo "=========================================="
echo "SDN-NIDPS Environment Setup"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "[1/10] Updating package manager..."
apt-get update
apt-get upgrade -y

echo "[2/10] Installing system dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    wget \
    curl \
    nano \
    net-tools \
    tcpdump \
    iperf3 \
    wireshark \
    openvswitch-switch \
    openvswitch-common \
    suricata \
    suricata-update \
    mininet \
    iperf \
    apache2-utils

echo "[3/10] Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo "[4/10] Creating directory structure..."
mkdir -p logs
mkdir -p models
mkdir -p config
mkdir -p database
mkdir -p /var/log/suricata

echo "[5/10] Setting up Suricata..."
cp config/suricata.yaml /etc/suricata/suricata.yaml
suricata-update

echo "[6/10] Creating database..."
python3 -c "from src.database.database import db; db"

echo "[7/10] Configuring OVS..."
systemctl start openvswitch-switch
ovs-vsctl show

echo "[8/10] Setting up logging..."
touch logs/nidps.log
chmod 666 logs/nidps.log

echo "[9/10] Installing additional Python packages..."
pip3 install python-nmap paramiko paho-mqtt

echo "[10/10] Verifying installation..."
python3 -c "import ryu; print('Ryu installed:', ryu.__version__)"
python3 -c "import mininet; print('Mininet installed')"
python3 -c "import flask; print('Flask installed:', flask.__version__)"

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Start Ryu controller: ryu-manager src/controller/sdn_controller.py"
echo "2. Start dashboard: python3 src/dashboard/app.py"
echo "3. Run topology: python3 src/network/topology.py simple"
echo "4. Run demo: ./scripts/run_demo.sh"
