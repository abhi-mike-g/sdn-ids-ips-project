# SDN-NIDPS

An educational SDN intrusion detection and prevention project. It combines an OS-Ken OpenFlow 1.3 controller, Suricata EVE alerts, SQLite persistence, an incident API, and a Flask dashboard.

## Run the no-network demo

Python 3.10–3.12 is recommended. The offline replay uses no Mininet, switch, or packet-capture privileges and never applies live blocking:

```bash
bash scripts/setup_environment.sh --demo
bash scripts/run_demo.sh --check
bash scripts/run_demo.sh
```

Open `http://127.0.0.1:5000`. The replay uses `orchestrator/demo_scenarios.jsonl`; it includes reconnaissance, UDP, SSH, web, MQTT, and DNS alert records across multiple lab hosts. The topology and flows are simulated from those records, and incident actions are marked simulated. Press Ctrl-C to stop the dashboard. Use `--replay FILE` to load another Suricata EVE JSONL file.

## Run the live isolated lab

The live mode requires Ubuntu 22.04/24.04, root, Open vSwitch, Mininet, and Suricata. It creates a local Mininet topology; it does not monitor your host's physical network interface.

```bash
bash scripts/setup_environment.sh --live
sudo bash scripts/start_system.sh
```

The live launcher starts the OS-Ken controller, Suricata on the Mininet switch interface, the incident orchestrator, and the dashboard. It opens the Mininet CLI for local connectivity checks. The dashboard is at `http://127.0.0.1:5000`; Ctrl-C or Ctrl-D shuts down the stack. Logs and SQLite files are stored under `logs/`.

Live mode has not been exercised on this host: it does not have Mininet, Open vSwitch, or Suricata installed. Suricata 7.0.17 did validate the repository rules and YAML configuration. The actual OpenFlow dataplane and packet capture should be checked in the supported Ubuntu lab.

## Configuration and tests

Project settings are in `config/controller_config.json`; `NIDPS_CONFIG` can point to an alternate JSON file. The control and dashboard APIs bind to loopback by default. Change network exposure only when you have configured appropriate access controls.

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m src.demo --check
```

For service endpoints and architecture details, see [docs/API_DOCS.md](docs/API_DOCS.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The optional attack simulator modules are intended for isolated labs only; the offline replay is the recommended demonstration path.
