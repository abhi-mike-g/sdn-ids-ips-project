r"""Main orchestration loop and CLI entrypoint.

Pipeline:
    eve.json --> normalise --> enrich --> correlate --> decide --> mitigate
                                                              \--> persist

Run it live against a real sensor:
    python -m orchestrator.orchestrator --eve /var/log/suricata/eve.json \
        --ryu-url http://127.0.0.1:8080 --api-port 5001 \
        --protected 10.0.0.254,10.0.0.10

Develop / demo it WITHOUT the full stack (no Suricata, no Ryu):
    python -m orchestrator.orchestrator --replay sample_eve.json --dry-run
"""
from __future__ import annotations

import argparse
import logging
import threading
import time

from . import eve_watcher
from .correlation import Correlator
from .enrichment import enrich
from .models import Alert, IncidentState, ResponseAction
from .policy import PolicyConfig, decide
from .ryu_client import RyuClient
from .store import Store

log = logging.getLogger("orchestrator")


class Orchestrator:
    def __init__(self, store, correlator, policy_cfg, ryu, clock=None, retry_interval=5):
        self.store, self.correlator = store, correlator
        self.policy_cfg, self.ryu = policy_cfg, ryu
        self.clock = clock or time.monotonic
        self.retry_interval = retry_interval
        self._lock = threading.RLock()
        self._applied = {}  # incident id -> (action, expiry)
        self._retry_after = {}
        self.correlator.on_close = self._close_incident

    def _close_incident(self, inc):
        self.store.upsert_incident(inc)
        self._applied.pop(inc.id, None)
        self._retry_after.pop(inc.id, None)

    def handle_raw(self, record):
        with self._lock:
            alert = Alert.from_eve(record)
            if alert is None or not alert.src_ip:
                return
            enrich(alert)
            inc = self.correlator.ingest(alert)
            self.store.insert_alert(alert, inc.id)
            saved = self.store.get_incident(inc.id)
            if saved and saved['state'] in ('resolved', 'false_positive'):
                inc.state = IncidentState(saved['state'])
                inc.action = ResponseAction.NONE
                inc.action_reason = 'Analyst closed this incident'
                self.store.upsert_incident(inc)
                return
            action, reason = decide(inc, self.policy_cfg)
            inc.action, inc.action_reason = action, reason
            if inc.state is IncidentState.NEW:
                inc.state = IncidentState.TRIAGED
            now = self.clock()
            previous_action, expires = self._applied.get(inc.id, (None, 0))
            needs_action = previous_action != action or now >= expires
            if (action in (ResponseAction.BLOCK, ResponseAction.RATE_LIMIT) and needs_action
                    and now >= self._retry_after.get(inc.id, 0)):
                inc.state = IncidentState.MITIGATING
                self.store.upsert_incident(inc)
                result = (self.ryu.block_src(inc.src_ip) if action is ResponseAction.BLOCK
                          else self.ryu.rate_limit_src(inc.src_ip))
                if result.success:
                    inc.state = IncidentState.SIMULATED if result.dry_run else IncidentState.MITIGATED
                    inc.mitigation_latency_ms = result.latency_ms
                    inc.flow_rule = result.detail
                    # Refresh before switch hard_timeout, including a sustained incident.
                    self._applied[inc.id] = action, now + max(1, self.ryu.hard_timeout * 0.8)
                    self._retry_after.pop(inc.id, None)
                    log.warning('%s %s: %s', action.value.upper(), inc.src_ip, result.detail)
                else:
                    inc.state = IncidentState.TRIAGED
                    inc.action_reason += ' | mitigation FAILED: ' + result.detail
                    self._retry_after[inc.id] = now + self.retry_interval
                    log.error('Mitigation failed for %s: %s', inc.src_ip, result.detail)
            elif inc.id in self._retry_after and saved:
                inc.action_reason = saved['action_reason']
            self.store.upsert_incident(inc)

    def set_incident_state(self, incident_id, state):
        with self._lock:
            row = self.store.get_incident(incident_id)
            if row is None:
                raise KeyError(incident_id)
            if row['action'] in ('block', 'rate_limit'):
                result = self.ryu.unblock_src(row['src_ip'])
                if not result.success:
                    raise RuntimeError('Unable to release mitigation: ' + result.detail)
            self.store.set_state(incident_id, state)
            for inc in self.correlator.active.values():
                if inc.id == incident_id:
                    inc.state, inc.action = state, ResponseAction.NONE
                    inc.action_reason = 'Analyst closed this incident'
            self._applied.pop(incident_id, None)
            self._retry_after.pop(incident_id, None)

    def flush(self):
        with self._lock:
            self.correlator.flush()

    def run_replay(self, path):
        count = 0
        for record in eve_watcher.read_alerts(path):
            self.handle_raw(record)
            count += 1
        self.flush()
        log.info('Replay complete: %d alerts processed', count)
        return count

    def run_live(self, path, from_start=False):
        for record in eve_watcher.tail_alerts(path, from_start=from_start):
            self.handle_raw(record)


def _start_api(store: Store, port: int, orchestrator=None) -> None:
    from .api import create_app
    app = create_app(store, orchestrator)
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port,
                               debug=False, use_reloader=False),
        daemon=True,
    )
    thread.start()
    log.info("Incident API listening on http://0.0.0.0:%d/api/incidents", port)


def main() -> None:
    p = argparse.ArgumentParser(description="SDN Security Orchestrator")
    p.add_argument("--eve", default="/var/log/suricata/eve.json",
                   help="path to Suricata eve.json (live mode)")
    p.add_argument("--replay", metavar="FILE",
                   help="replay an existing eve.json once, then exit")
    p.add_argument("--db", default="orchestrator.db", help="SQLite path")
    p.add_argument("--ryu-url", default="http://127.0.0.1:8080",
                   help="base URL of the ofctl_rest API")
    p.add_argument("--dry-run", action="store_true",
                   help="log mitigations instead of calling the controller")
    p.add_argument("--window", type=float, default=120.0,
                   help="incident correlation window (seconds)")
    p.add_argument("--protected", default="",
                   help="comma-separated IPs that must never be auto-blocked")
    p.add_argument("--api-port", type=int, default=0,
                   help="if set, serve the incident REST API on this port")
    p.add_argument("--keep-alive", action="store_true", help="keep the API alive after replay")
    p.add_argument("--from-start", action="store_true",
                   help="in live mode, also process pre-existing lines")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    store = Store(args.db)
    correlator = Correlator(window_seconds=args.window)
    protected = {ip.strip() for ip in args.protected.split(",") if ip.strip()}
    policy_cfg = PolicyConfig(protected_ips=protected)
    ryu = RyuClient(base_url=args.ryu_url, dry_run=args.dry_run)
    orch = Orchestrator(store, correlator, policy_cfg, ryu)

    if args.api_port:
        _start_api(store, args.api_port, orch)

    if args.replay:
        orch.run_replay(args.replay)
        # Print a compact summary so replay is useful on its own.
        for inc in store.recent_incidents(50):
            print(f"  [{inc['state']:>13}] {inc['src_ip']:<15} "
                  f"action={inc['action']:<10} "
                  f"alerts={inc['alert_count']:<5} "
                  f"stride={inc['stride']} "
                  f"lat={inc['mitigation_latency_ms']}")
        if args.keep_alive and args.api_port:
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                pass
    else:
        try:
            orch.run_live(args.eve, from_start=args.from_start)
        except KeyboardInterrupt:
            log.info("Shutting down")
            orch.flush()


if __name__ == "__main__":
    main()
