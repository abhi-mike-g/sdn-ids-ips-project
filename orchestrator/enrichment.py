"""Map raw Suricata alerts onto STRIDE categories, MITRE ATT&CK techniques,
and a confidence prior.

IMPORTANT -- READ THIS BEFORE QUOTING ANY NUMBER:
The `confidence` values below are hand-set *priors*. They express how specific
and reliable each class of signature tends to be -- NOT a measured precision.
Do not present them as a detection-quality metric. Calibrate them against the
evaluation harness (replaying labelled pcaps with ground truth) and only then
report measured precision/recall.
"""
from __future__ import annotations

from .models import Alert, Stride

# Ordered rules, first match wins.
#   (keyword_lowercase, stride, [mitre_technique_ids], confidence_prior)
_RULES = [
    ("syn flood",         Stride.DOS,             ["T1499.001"], 0.85),
    ("udp flood",         Stride.DOS,             ["T1499.001"], 0.85),
    ("icmp flood",        Stride.DOS,             ["T1499"],     0.85),
    ("slowloris",         Stride.DOS,             ["T1499.002"], 0.80),
    ("amplification",     Stride.DOS,             ["T1498.002"], 0.80),
    ("flood",             Stride.DOS,             ["T1499"],     0.70),
    ("dos",               Stride.DOS,             ["T1499"],     0.60),
    ("nmap",              Stride.INFO_DISCLOSURE, ["T1046"],     0.80),
    ("port scan",         Stride.INFO_DISCLOSURE, ["T1046"],     0.80),
    ("xmas scan",         Stride.INFO_DISCLOSURE, ["T1046"],     0.80),
    ("null scan",         Stride.INFO_DISCLOSURE, ["T1046"],     0.80),
    ("scan",              Stride.INFO_DISCLOSURE, ["T1595"],     0.60),
    ("recon",             Stride.INFO_DISCLOSURE, ["T1595"],     0.60),
    ("sql injection",     Stride.ELEVATION,       ["T1190"],     0.80),
    ("xss",               Stride.ELEVATION,       ["T1059.007"], 0.75),
    ("command injection", Stride.ELEVATION,       ["T1190"],     0.80),
    ("brute force",       Stride.ELEVATION,       ["T1110"],     0.80),
    ("ssh",               Stride.ELEVATION,       ["T1110"],     0.60),
    ("rdp",               Stride.ELEVATION,       ["T1110"],     0.60),
    ("arp spoof",         Stride.SPOOFING,        ["T1557.002"], 0.80),
    ("dns cache poison",  Stride.SPOOFING,        ["T1557"],     0.75),
    ("dns spoof",         Stride.SPOOFING,        ["T1557"],     0.75),
    ("spoof",             Stride.SPOOFING,        ["T1557"],     0.60),
    ("session hijack",    Stride.TAMPERING,       ["T1557"],     0.70),
    ("fragmentation",     Stride.TAMPERING,       ["T1565"],     0.55),
    ("injection",         Stride.TAMPERING,       ["T1565"],     0.50),
    ("log",               Stride.REPUDIATION,     ["T1070"],     0.60),
]


def enrich(alert: Alert) -> Alert:
    """Attach STRIDE, MITRE, and a confidence prior to an alert in place."""
    sig = alert.signature.lower()
    for keyword, stride, mitre, conf in _RULES:
        if keyword in sig:
            alert.stride = stride
            alert.mitre = list(mitre)
            alert.confidence = conf
            return alert
    alert.stride = Stride.UNKNOWN
    alert.mitre = []
    alert.confidence = 0.40
    return alert
