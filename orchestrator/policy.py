"""Decision engine: given an incident, choose a response action.

Two design choices worth defending to an examiner:

  * PROTECTED ALLOWLIST. Certain IPs (gateway, controller, DNS resolver, the
    analyst's own host) are NEVER auto-blocked. An IPS that can be goaded into
    blocking core infrastructure -- e.g. by an attacker spoofing the gateway as
    the source of a 'flood' -- is a denial-of-service *amplifier*, not a
    defence. This single rule prevents the most common self-inflicted outage.

  * CHAIN ESCALATION. Several distinct STRIDE categories from one source (scan
    THEN brute force THEN injection) is a stronger signal than any single
    alert, so we escalate the effective severity by one level. This is where
    correlation earns its keep.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Incident, ResponseAction, Severity


@dataclass
class PolicyConfig:
    protected_ips: set = field(default_factory=set)
    auto_block_min_severity: Severity = Severity.HIGH
    auto_block_min_confidence: float = 0.70
    rate_limit_min_severity: Severity = Severity.MEDIUM
    chain_escalation_categories: int = 2   # >= this many STRIDE cats -> escalate
    sustained_alert_count: int = 100       # >= this many alerts -> escalate (volume)


def decide(inc: Incident, cfg: PolicyConfig) -> tuple:
    """Return (ResponseAction, human-readable reason)."""
    if inc.src_ip in cfg.protected_ips:
        return ResponseAction.MONITOR, f"{inc.src_ip} is on the protected allowlist"

    severity = inc.max_severity
    reasons = []

    # Breadth: several distinct STRIDE categories from one source.
    if (len(inc.stride) >= cfg.chain_escalation_categories
            and severity < Severity.CRITICAL):
        severity = Severity(min(int(severity) + 1, int(Severity.CRITICAL)))
        reasons.append("multi-stage chain")

    # Volume: a sustained burst (flood) is worse than a single packet, even at
    # the same per-alert severity.
    if (inc.alert_count >= cfg.sustained_alert_count
            and severity < Severity.CRITICAL):
        severity = Severity(min(int(severity) + 1, int(Severity.CRITICAL)))
        reasons.append("sustained volume")

    esc = f" (escalated: {', '.join(reasons)})" if reasons else ""
    detail = (f"severity={severity.name}{esc}, "
              f"{len(inc.stride)} STRIDE categories, "
              f"confidence={inc.max_confidence:.2f}, "
              f"{inc.alert_count} alerts")

    if (severity >= cfg.auto_block_min_severity
            and inc.max_confidence >= cfg.auto_block_min_confidence):
        return ResponseAction.BLOCK, detail
    if severity >= cfg.rate_limit_min_severity:
        return ResponseAction.RATE_LIMIT, detail
    return ResponseAction.MONITOR, detail
