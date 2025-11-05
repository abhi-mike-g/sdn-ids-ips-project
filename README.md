# SDN-Based Scalable Network Intrusion Detection & Prevention System (NIDPS)

An advanced cybersecurity system combining Software-Defined Networking (SDN) with threat modeling and real-time intrusion detection/prevention capabilities.

-----

## Features

  * **Real-time Threat Detection**: Leveraging Suricata IDS and machine learning
  * **Automated Threat Response**: Dynamic policy enforcement through SDN
  * **Threat Modeling Integration**: Microsoft Threat Modeling Tool integration (STRIDE)
  * **Scalable Architecture**: Support for large network deployments
  * **Comprehensive Dashboard**: Real-time visualization and monitoring
  * **Attack Simulation**: Built-in attack scenarios for testing and demonstration
  * **Multi-layer Detection**: Signature-based, anomaly-based, and ML-based detection

-----

## System Requirements

  * **OS**: Ubuntu 20.04 LTS or later
  * **Python**: Python 3.8+
  * **RAM**: 4GB minimum (**8GB recommended**)
  * **Disk**: 10GB for database and logs
  * **Network**: Standard network interface for testing

-----

## Quick Start

### 1\. Installation

```bash
git clone <repository-url>
cd sdn-nidps-project
sudo bash scripts/setup_environment.sh
```

### 2\. Configuration

Edit `config/controller_config.json` for your environment:

```json
{
  "controller": {
    "host": "0.0.0.0",
    "port": 6653
  },
  "database": {
    "url": "sqlite:///logs/nidps.db"
  }
}
```

### 3\. Start System

```bash
sudo bash scripts/start_system.sh
```

### 4\. Access Dashboard

Open browser and navigate to: `http://localhost:5000`

### 5\. Run Demo

```bash
bash scripts/run_demo.sh
```

-----

## Architecture

### Components

1.  **Ryu SDN Controller**: Manages network switches and flow rules
2.  **Suricata IDS**: Network-based intrusion detection
3.  **Threat Detector**: Real-time threat analysis engine
4.  **Policy Enforcer**: Automated response mechanisms
5.  **Dashboard**: Web-based monitoring interface
6.  **Attack Simulator**: Testing and demonstration tools

### Data Flow

```text
Network Traffic → Suricata IDS → Threat Detector → Policy Enforcer → Flow Rules
↓
Dashboard ← Database ← Metrics Collector
```

-----

## Usage

### Starting Individual Components

```bash
# Start Ryu controller
ryu-manager src/controller/sdn_controller.py

# Start dashboard (in another terminal)
python3 src/dashboard/app.py

# Create network topology
python3 src/network/topology.py simple

# Run attack simulation
python3 -c "
from src.attacks.attack_manager import AttackManager
manager = AttackManager()
manager.run_demo_scenario(target='10.0.0.2')
"
```

### Dashboard Features

  * **Real-time Alerts**: View detected threats as they occur
  * **Network Topology**: Visualize network structure and connections
  * **Attack Logs**: Comprehensive logging of all security events
  * **Performance Metrics**: System and network performance monitoring
  * **IP Blocking**: Manual threat response capability

### API Endpoints

| Category | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **Authentication** | `GET` | `/api/status` | System status |
| **Topology** | `GET` | `/api/topology` | Network topology data |
| **Alerts** | `GET` | `/api/alerts` | Recent alerts (sortable/filterable) |
| | `POST` | `/api/block_ip` | Block IP address |
| | `POST` | `/api/unblock_ip` | Unblock IP address |
| **Metrics** | `GET` | `/api/metrics` | Real-time system metrics |
| | `GET` | `/api/metrics/history` | Historical metrics |
| **Flows** | `GET` | `/api/flows` | Active OpenFlow rules |

-----

## Threat Model

The system implements **STRIDE** threat modeling with 33 identified threats:

  * **S**poofing: Controller/Switch authentication
  * **T**ampering: Flow rule integrity, input validation
  * **R**epudiation: Comprehensive audit logging
  * **I**nformation **D**isclosure: Access controls, encryption
  * **D**enial of **S**ervice: Rate limiting, resource management
  * **E**levation of **P**rivilege: Role-based access control

See `threat_model/` directory for detailed threat analysis.

-----

## Attack Scenarios

### Supported Attacks

1.  **Port Scan**: Network reconnaissance
2.  **SYN Flood**: DoS attack
3.  **UDP Flood**: Volume-based attack
4.  **ICMP Flood**: Bandwidth attack
5.  **ARP Spoofing**: Man-in-the-middle
6.  **SQL Injection**: Database attack
7.  **Brute Force**: Authentication attack
8.  **MQTT Injection**: IoT-specific attack

### Running Attacks

```python
from src.attacks.attack_manager import AttackManager

manager = AttackManager()
attack_id = manager.execute_attack(
    'dos',
    target='10.0.0.2',
    duration=30,
    packet_rate=100
)
```

-----

## Performance Metrics

  * **Detection Latency**: \<100ms
  * **Throughput**: 100k+ packets/second
  * **Database**: SQLite (scalable to PostgreSQL)
  * **Supports up to 1000 concurrent flows**

-----

## Troubleshooting

### Controller won't connect to switches

```bash
# Check Ryu is running
ps aux | grep ryu

# Check port 6653
netstat -tlnp | grep 6653

# Restart controller
pkill -f ryu-manager
ryu-manager src/controller/sdn_controller.py
```

### Suricata not generating alerts

```bash
# Check Suricata status
sudo systemctl status suricata

# Check EVE log
tail -f /var/log/suricata/eve.json

# Restart Suricata
sudo systemctl restart suricata
```

### Database issues

```bash
# Check database file
ls -lh logs/nidps.db

# Reinitialize database
rm logs/nidps.db
python3 -c "from src.database.database import db"
```

-----

## Documentation

  * `docs/ARCHITECTURE.md` - System architecture details
  * `docs/API_DOCS.md` - API reference
  * `docs/DEPLOYMENT.md` - Production deployment guide
  * `threat_model/` - Threat modeling documentation

-----

## Contributing

1.  Create feature branch
2.  Make changes
3.  Run tests
4.  Submit pull request

-----

## License

This project is for educational purposes.

-----

## Support

For issues and questions:

  * Check documentation first
  * Review logs in `logs/` directory
  * Create GitHub issue with details

-----

## Authors

  * Abhidutta Mukund Giri
  * Avishi Bansal
  * Piyush

-----

## Acknowledgments

  * Manipal Institute of Technology
  * Ryu SDN Project
  * Suricata IDS Project
  * Mininet Network Simulator

-----
