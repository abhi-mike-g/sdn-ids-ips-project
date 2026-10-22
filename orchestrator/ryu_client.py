"""Adapter for this project's controller API.

Latency measures the controller HTTP response, not switch acknowledgement or
packet loss. A live network test is required to verify dataplane enforcement.
"""
from dataclasses import dataclass
from typing import Optional
import ipaddress
import time
import requests


@dataclass
class MitigationResult:
    success: bool
    latency_ms: Optional[float]
    dry_run: bool
    detail: str


class RyuClient:
    # Retained class name for existing orchestrator imports; supports the OS-Ken
    # controller shipped here via its explicit /nidps API.
    def __init__(self, base_url='http://127.0.0.1:8080', drop_priority=40000,
                 hard_timeout=300, dry_run=False, request_timeout=3.0):
        self.base_url = base_url.rstrip('/')
        self.hard_timeout = hard_timeout
        self.dry_run = dry_run
        self.request_timeout = request_timeout

    def _apply(self, action, src_ip, **extra):
        src_ip = str(ipaddress.IPv4Address(src_ip))
        if self.dry_run:
            return MitigationResult(True, None, True, f'[dry-run] would {action} {src_ip}')
        started = time.perf_counter()
        try:
            response = requests.post(self.base_url + '/nidps/' + action,
                                     json={'ip': src_ip, 'duration': self.hard_timeout, **extra},
                                     timeout=self.request_timeout)
            data = response.json()
            if not response.ok or not data.get('success') or not data.get('switches'):
                return MitigationResult(False, None, False, data.get('error', 'No switches confirmed'))
            return MitigationResult(True, (time.perf_counter() - started) * 1000, False,
                                    f"{action} {src_ip} submitted to {data['switches']} switches")
        except (requests.RequestException, ValueError) as exc:
            return MitigationResult(False, None, False, str(exc))

    def block_src(self, src_ip):
        return self._apply('block_ip', src_ip)

    def rate_limit_src(self, src_ip, rate_kbps=1000):
        return self._apply('rate_limit', src_ip, rate_kbps=rate_kbps)

    def unblock_src(self, src_ip):
        return self._apply('unblock_ip', src_ip)
