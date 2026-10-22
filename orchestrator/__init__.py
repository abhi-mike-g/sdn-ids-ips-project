"""SDN Security Orchestrator.

An alert-driven orchestration layer that sits between a detection engine
(Suricata) and an SDN control plane (Ryu / os-ken). It ingests alerts,
enriches them with STRIDE + MITRE ATT&CK context, correlates them into
incidents, decides on a response via a configurable policy, installs the
mitigating OpenFlow rule, and measures how long that took.

This package deliberately does NOT detect attacks itself. Detection is
Suricata's job. This layer's value is the incident lifecycle and the
automated, measured response.
"""

__all__ = [
    "models",
    "eve_watcher",
    "enrichment",
    "correlation",
    "store",
    "policy",
    "ryu_client",
    "orchestrator",
    "api",
]
