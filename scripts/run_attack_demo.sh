# scripts/run_attack_demo.sh
#!/bin/bash

echo "=== Attack Demonstration Script ==="

# Scenario 1: Port Scan
echo "[Demo 1/7] Port Scan Attack"
python3 attack_simulation/scenarios/port_scan.py --target 192.168.1.10
sleep 5

# Scenario 2: DoS
echo "[Demo 2/7] SYN Flood Attack"
python3 attack_simulation/scenarios/dos_attack.py --target 192.168.1.10 --duration 30
sleep 5

# Scenario 3: Brute Force
echo "[Demo 3/7] SSH Brute Force"
python3 attack_simulation/scenarios/brute_force.py --target 192.168.1.10 --service ssh
sleep 5

# Scenario 4: MITM
echo "[Demo 4/7] ARP Spoofing"
python3 attack_simulation/scenarios/mitm_attack.py --victim 192.168.1.10 --gateway 192.168.1.1
sleep 5

# Scenario 5: SQL Injection
echo "[Demo 5/7] SQL Injection"
python3 attack_simulation/scenarios/sql_injection.py --url http://192.168.1.10/login
sleep 5

# Scenario 6: XSS
echo "[Demo 6/7] Cross-Site Scripting"
python3 attack_simulation/scenarios/xss_attack.py --url http://192.168.1.10/search
sleep 5

# Scenario 7: MQTT Injection
echo "[Demo 7/7] IoT MQTT Attack"
python3 attack_simulation/scenarios/mqtt_injection.py --broker 192.168.1.10:1883

echo "=== Demo Complete - Check Dashboard for Results ==="
