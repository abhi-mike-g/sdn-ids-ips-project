"""Correlate individual alerts into incidents.

Incidents are keyed by SOURCE IP (the 'actor'). Every alert from one source
within a sliding inactivity window folds into a single incident. This does two
things a raw alert feed cannot:

  1. Collapses a flood -- thousands of identical alerts -- into ONE incident.
  2. Stitches a multi-stage sequence (recon -> brute force -> exfil, same
     source) into ONE attack chain, which is what a SOC analyst wants to see
     and what lets the policy engine escalate on breadth of behaviour.

When an incident sees no new alerts for `window_seconds`, it is closed. This is
a simple, explainable model; a production system would add flow-key and
victim-side correlation, but source-actor grouping is the right first cut for a
lab demonstration.
"""
from __future__ import annotations

from typing import Callable, Optional

from .models import Alert, Incident, IncidentState


class Correlator:
    def __init__(self, window_seconds: float = 120.0,
                 on_close: Optional[Callable[[Incident], None]] = None):
        self.window = window_seconds
        self.active: dict = {}  # src_ip -> Incident
        self.on_close = on_close

    def _expire(self, now_ts: float) -> None:
        stale = [ip for ip, inc in self.active.items()
                 if now_ts - inc.last_seen_ts > self.window]
        for ip in stale:
            inc = self.active.pop(ip)
            if inc.state in (IncidentState.NEW, IncidentState.TRIAGED):
                # Decayed without ever being escalated to a block.
                inc.state = IncidentState.RESOLVED
            if self.on_close:
                self.on_close(inc)

    def ingest(self, alert: Alert) -> Incident:
        now_ts = alert.timestamp.timestamp()
        self._expire(now_ts)
        inc = self.active.get(alert.src_ip)
        if inc is None:
            inc = Incident.new(alert.src_ip, alert.timestamp)
            self.active[alert.src_ip] = inc
        inc.fold(alert)
        return inc

    def flush(self) -> None:
        """Close every active incident (end of replay / shutdown)."""
        for inc in list(self.active.values()):
            if self.on_close:
                self.on_close(inc)
        self.active.clear()
