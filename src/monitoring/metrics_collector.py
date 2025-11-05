import psutil
import time
import threading
from ..database.database import db
from ..utils.logger import setup_logger

logger = setup_logger('metrics_collector')

class MetricsCollector:
    """Collect system and network metrics"""
    
    def __init__(self, interval=5):
        self.interval = interval
        self.running = False
        self._thread = None
        self.current_metrics = {}
        
    def start(self):
        """Start metrics collection"""
        if self.running:
            return
        
        self.running = True
        self._thread = threading.Thread(target=self._collect_loop, daemon=True)
        self._thread.start()
        logger.info("Metrics collector started")
    
    def stop(self):
        """Stop metrics collection"""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Metrics collector stopped")
    
    def _collect_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                self.current_metrics = self.collect_metrics()
                self._store_metrics(self.current_metrics)
                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
    
    def collect_metrics(self):
        """Collect all metrics"""
        return {
            'cpu': self._collect_cpu_metrics(),
            'memory': self._collect_memory_metrics(),
            'disk': self._collect_disk_metrics(),
            'network': self._collect_network_metrics()
        }
    
    def _collect_cpu_metrics(self):
        """Collect CPU metrics"""
        return {
            'percent': psutil.cpu_percent(interval=1),
            'count': psutil.cpu_count(),
            'per_cpu': psutil.cpu_percent(interval=1, percpu=True)
        }
    
    def _collect_memory_metrics(self):
        """Collect memory metrics"""
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'percent': mem.percent,
            'used': mem.used,
            'free': mem.free
        }
    
    def _collect_disk_metrics(self):
        """Collect disk metrics"""
        disk = psutil.disk_usage('/')
        io = psutil.disk_io_counters()
        
        return {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent,
            'read_bytes': io.read_bytes,
            'write_bytes': io.write_bytes
        }
    
    def _collect_network_metrics(self):
        """Collect network metrics"""
        net_io = psutil.net_io_counters()
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    
    def _store_metrics(self, metrics):
        """Store metrics in database"""
        try:
            db.insert_metrics({
                'cpu_usage': metrics['cpu']['percent'],
                'memory_usage': metrics['memory']['percent'],
                'active_flows': 0,  # Will be updated by controller
                'threats_detected': 0,  # Will be updated by detector
                'throughput_mbps': self._calculate_throughput(metrics['network']),
                'latency_ms': 0  # Will be measured separately
            })
        except Exception as e:
            logger.error(f"Failed to store metrics: {e}")
    
    def _calculate_throughput(self, network_metrics):
        """Calculate network throughput in Mbps"""
        if hasattr(self, '_last_network_metrics'):
            elapsed = self.interval
            bytes_diff = (network_metrics['bytes_sent'] + network_metrics['bytes_recv']) - \
                        (self._last_network_metrics['bytes_sent'] + self._last_network_metrics['bytes_recv'])
            mbps = (bytes_diff * 8) / (elapsed * 1000000)
            self._last_network_metrics = network_metrics
            return mbps
        
        self._last_network_metrics = network_metrics
        return 0.0
    
    def get_current_metrics(self):
        """Get current metrics"""
        return self.current_metrics
