# SDN Security Orchestrator

The decision layer between your **detection engine (Suricata)** and your **SDN
control plane (Ryu / os-ken)**. It does *not* detect attacks — Suricata does
that. Its job is the incident lifecycle: ingest alerts, enrich them, correlate
them into incidents, decide on a response via policy, install the mitigating
OpenFlow rule, and **measure how long that took**.

This is the piece that reframes the project from "Suricata + Ryu integration"
into "an SDN security orchestration platform."

```
 Suricata --> eve.json --> [ watcher --> enrich --> correlate --> policy --> mitigate ] --> Ryu/os-ken (ofctl_rest) --> flows
                                            |                                   |
                                            +----------- SQLite store ----------+
                                                              |
                                                        Flask API  --> dashboard
```

## What each module does

| Module            | Responsibility |
|-------------------|----------------|
| `models.py`       | `Alert`, `Incident`, and the STRIDE / state / severity / action enums. |
| `eve_watcher.py`  | Tail `eve.json` live (or read once for replay). Handles rotation + partial lines. |
| `enrichment.py`   | Signature → STRIDE category + MITRE ATT&CK technique + confidence prior. |
| `correlation.py`  | Fold alerts into incidents keyed by source IP. Collapses floods; stitches attack chains. |
| `policy.py`       | Decide MONITOR / RATE_LIMIT / BLOCK. Allowlist + chain + volume escalation. |
| `ryu_client.py`   | Install drop flows via stock `ofctl_rest`; measure real install latency. |
| `store.py`        | SQLite persistence for incidents and alerts. |
| `api.py`          | Read + analyst-action REST API for the dashboard. |
| `orchestrator.py` | Wires it together; CLI entrypoint; replay/live modes. |

## Run it right now (no Suricata, no Ryu needed)

```bash
pip install -r requirements.txt          # add --break-system-packages on Fedora if needed
python -m orchestrator.orchestrator --replay sample_eve.json --dry-run --protected 10.0.0.254
```

`--replay` reads a static `eve.json` once; `--dry-run` logs the flow it *would*
install instead of calling a controller. This lets you develop and demo the
whole decision pipeline before the live stack exists. A `sample_eve.json`
generator is described in the parent chat; drop any real Suricata `eve.json`
here to replay it.

## Run it live (once Suricata + the controller are up)

1. Launch your controller with `ofctl_rest` loaded so the orchestrator can
   install flows through the stock REST API — no change to your controller code:

   ```bash
   ryu-manager   your_controller.py ryu.app.ofctl_rest      # Ryu
   osken-manager your_controller.py os_ken.app.ofctl_rest   # os-ken (modern Python)
   ```

2. Start the orchestrator pointed at the live sensor, with the API on:

   ```bash
   python -m orchestrator.orchestrator \
       --eve /var/log/suricata/eve.json \
       --ryu-url http://127.0.0.1:8080 \
       --api-port 5001 \
       --protected 10.0.0.254,10.0.0.10
   ```

3. Point the dashboard at `http://<host>:5001/api/incidents` and `/api/stats`.

The `ryu_client` talks to `ofctl_rest` over HTTP, so it behaves identically
whether you run Ryu or os-ken.

## Two honesty notes (put these in your report, verbatim if you like)

- **Confidence values are priors, not measurements.** The numbers in
  `enrichment.py` express how specific each signature class tends to be. They
  are *not* measured precision. Calibrate them with the evaluation harness
  (labelled pcaps + ground truth) before quoting any detection-quality figure.

- **`mitigation_latency_ms` is REST-confirmed, not dataplane-confirmed.** It is
  the wall-clock time from starting the block to every switch ACKing the
  flow-add REST call. It does not include an OpenFlow barrier. In dry-run it is
  `None` — the code never fabricates a plausible latency.

## Deliberately left for the next step (the evaluation harness)

- Replaying a *labelled* dataset (e.g. a CIC-IDS2017 subset, or your own
  captured+labelled pcaps) to compute measured precision / recall / FP-rate.
- Sweeping topology size (4 → 20 → 50 → 100 hosts) and plotting controller CPU,
  flow-install time, and detection→mitigation latency vs host count. That plot
  is what earns the word "Scalable" in the project title.
