import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from ..utils.logger import setup_logger

logger = setup_logger('traffic_analyzer')

class TrafficAnalyzer:
    def __init__(self):
        self.flow_cache = defaultdict(dict)  # {(src_ip, dst_ip): flow_data}
        self.baseline_stats = {}
        
    def analyze_flow(self, flow_features):
        """Analyze flow for anomalies"""
        flow_key = (
            flow_features.get('src_ip'),
            flow_features.get('dst_ip'),
            flow_features.get('dst_port')
        )
        
        # Update flow statistics
        self._update_flow_stats(flow_key, flow_features)
        
        # Detect anomalies
        anomalies = []
        
        # Check packet rate
        if self._detect_packet_rate_anomaly(flow_key):
            anomalies.append('HIGH_PACKET_RATE')
        
        # Check payload size
        if self._detect_payload_anomaly(flow_features):
            anomalies.append('UNUSUAL_PAYLOAD')
        
        # Check protocol anomaly
        if self._detect_protocol_anomaly(flow_features):
            anomalies.append('PROTOCOL_ANOMALY')
        
        return {
            'has_anomaly': len(anomalies) > 0,
            'anomalies': anomalies,
            'confidence': self._calculate_confidence(anomalies)
        }
    
    def _update_flow_stats(self, flow_key, features):
        """Update flow statistics"""
        if flow_key not in self.flow_cache:
            self.flow_cache[flow_key] = {
                'packet_count': 0,
                'byte_count': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'packets': []
            }
        
        flow = self.flow_cache[flow_key]
        flow['packet_count'] += 1
        flow['byte_count'] += features.get('total_length', 0)
        flow['last_seen'] = datetime.now()
        flow['packets'].append(features)
        
        # Keep only recent packets
        if len(flow['packets']) > 100:
            flow['packets'] = flow['packets'][-100:]
    
    def _detect_packet_rate_anomaly(self, flow_key):
        """Detect abnormal packet rate"""
        if flow_key not in self.flow_cache:
            return False
        
        flow = self.flow_cache[flow_key]
        duration = (flow['last_seen'] - flow['first_seen']).total_seconds()
        
        if duration > 0:
            packet_rate = flow['packet_count'] / duration
            # Threshold: 100 packets/second
            if packet_rate > 100:
                return True
        
        return False
    
    def _detect_payload_anomaly(self, features):
        """Detect unusual payload sizes"""
        payload_size = features.get('total_length', 0)
        
        # Very small or very large payloads can be suspicious
        if payload_size < 20 or payload_size > 1500:
            return True
        
        return False
    
    def _detect_protocol_anomaly(self, features):
        """Detect protocol-specific anomalies"""
        protocol = features.get('protocol')
        dst_port = features.get('dst_port')
        
        # Check for protocol-port mismatches
        expected_protocols = {
            80: 6,   # HTTP - TCP
            443: 6,  # HTTPS - TCP
            53: 17,  # DNS - UDP
            22: 6,   # SSH - TCP
        }
        
        if dst_port in expected_protocols:
            if protocol != expected_protocols[dst_port]:
                return True
        
        return False
    
    def _calculate_confidence(self, anomalies):
        """Calculate confidence score"""
        if not anomalies:
            return 0.0
        
        # More anomalies = higher confidence
        return min(1.0, len(anomalies) * 0.3)
    
    def get_flow_statistics(self):
        """Get overall flow statistics"""
        total_flows = len(self.flow_cache)
        total_packets = sum(f['packet_count'] for f in self.flow_cache.values())
        total_bytes = sum(f['byte_count'] for f in self.flow_cache.values())
        
        return {
            'total_flows': total_flows,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'active_flows': self._count_active_flows()
        }
    
    def _count_active_flows(self):
        """Count flows active in last 60 seconds"""
        cutoff = datetime.now() - timedelta(seconds=60)
        return sum(1 for f in self.flow_cache.values() 
                   if f['last_seen'] > cutoff)
