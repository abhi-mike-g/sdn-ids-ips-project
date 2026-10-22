"""Measured host counters; unknown detection latency remains null."""
import threading
import time
import psutil
from ..database.database import db


class MetricsCollector:
    def __init__(self, interval=5, database=None):
        self.interval = interval
        self.db = database or db
        self.current_metrics = {}
        self.running = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._last = None

    def collect_metrics(self):
        with self._lock:
            now = time.monotonic()
            io = psutil.net_io_counters()
            byte_total = io.bytes_sent + io.bytes_recv
            packet_total = io.packets_sent + io.packets_recv
            mbps = pps = None
            if self._last is not None:
                old_time, old_bytes, old_packets = self._last
                elapsed = now - old_time
                if elapsed > 0:
                    mbps = max(0, byte_total - old_bytes) * 8 / elapsed / 1000000
                    pps = max(0, packet_total - old_packets) / elapsed
            self._last = now, byte_total, packet_total
            self.current_metrics = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'network': {'bytes_sent': io.bytes_sent, 'bytes_recv': io.bytes_recv},
                'packets_per_second': pps, 'throughput_mbps': mbps,
                'latency_ms': None, 'scope': 'host network interfaces'}
            return dict(self.current_metrics)

    def _store_metrics(self, metrics):
        self.db.insert_metrics({'cpu_usage': metrics['cpu_percent'],
                                'memory_usage': metrics['memory_percent'],
                                'active_flows': len(self.db.get_active_flow_rules()),
                                'threats_detected': self.db.statistics()['total_alerts'],
                                'throughput_mbps': metrics['throughput_mbps'], 'latency_ms': None})

    def _collect_loop(self):
        while not self._stop.is_set():
            self._store_metrics(self.collect_metrics())
            self._stop.wait(self.interval)

    def start(self):
        if not self.running:
            self.running = True
            self._stop.clear()
            self._thread = threading.Thread(target=self._collect_loop, daemon=True)
            self._thread.start()

    def stop(self):
        self.running = False
        self._stop.set()
        if hasattr(self, '_thread'):
            self._thread.join(timeout=5)

    def get_current_metrics(self):
        with self._lock:
            return dict(self.current_metrics)
