import time
from collections import deque
from ..utils.logger import setup_logger

logger = setup_logger('performance_monitor')

class PerformanceMonitor:
    """Monitor system performance metrics"""
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.detection_latencies = deque(maxlen=window_size)
        self.flow_installation_times = deque(maxlen=window_size)
        self.packet_processing_times = deque(maxlen=window_size)
        
    def record_detection_latency(self, latency_ms):
        """Record threat detection latency"""
        self.detection_latencies.append(latency_ms)
    
    def record_flow_installation(self, duration_ms):
        """Record flow rule installation time"""
        self.flow_installation_times.append(duration_ms)
    
    def record_packet_processing(self, duration_ms):
        """Record packet processing time"""
        self.packet_processing_times.append(duration_ms)
    
    def get_statistics(self):
        """Get performance statistics"""
        return {
            'detection_latency': self._calculate_stats(self.detection_latencies),
            'flow_installation': self._calculate_stats(self.flow_installation_times),
            'packet_processing': self._calculate_stats(self.packet_processing_times)
        }
    
    def _calculate_stats(self, data):
        """Calculate statistics for data series"""
        if not data:
            return {'min': 0, 'max': 0, 'avg': 0, 'count': 0}
        
        return {
            'min': min(data),
            'max': max(data),
            'avg': sum(data) / len(data),
            'count': len(data)
        }
