#!/bin/bash

echo "Stopping SDN-NIDPS System..."

# Kill Python processes
pkill -f "ryu-manager" || true
pkill -f "sdn_controller" || true
pkill -f "dashboard" || true
pkill -f "metrics_collector" || true
pkill -f "mininet" || true

# Stop Suricata
sudo systemctl stop suricata || true

# Cleanup OVS
sudo ovs-vsctl list-br | xargs -I {} sudo ovs-vsctl del-br {} || true

# Cleanup Mininet
sudo mn -c || true

echo "System stopped"
