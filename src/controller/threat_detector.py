from ..utils.logger import setup_logger
from ..detection.ml_detector import MLDetector
import time
from collections import deque
from ..utils.config import config

logger = setup_logger('threat_detector')

class ThreatDetector:
    def __init__(self, clock=None):
        self.ml_detector = MLDetector()
        self.suspicious_ips = {}  # {ip: {'count': int, 'first_seen': timestamp}}
        self.port_scan_threshold = config.get('detection.port_scan_threshold', 10)
        self.connection_threshold = config.get('detection.connection_threshold', 100)
        self.window = 60.0
        self.clock = clock or time.monotonic
        
    def analyze_packet(self, flow_features):
        """Analyze packet for threats"""
        threats = []
        
        # Check for port scanning
        if self._detect_port_scan(flow_features):
            threats.append('PORT_SCAN')
        
        # Check for DoS patterns
        if self._detect_dos(flow_features):
            threats.append('DOS_ATTACK')
        
        # Check for suspicious protocols/ports
        if self._detect_suspicious_port(flow_features):
            threats.append('SUSPICIOUS_PORT')
        
        # ML-based detection
        if self.ml_detector.is_loaded() and all(k in flow_features for k in ('packet_count', 'byte_count', 'duration')):
            ml_result = self.ml_detector.predict(flow_features)
            if ml_result['is_malicious']:
                threats.append(ml_result['attack_type'])
        
        if threats:
            return {
                'is_threat': True,
                'threat_type': ', '.join(threats),
                'severity': self._calculate_severity(threats),
                'signature': f"Multiple threats detected: {threats}",
                'description': self._generate_description(threats, flow_features)
            }
        
        return {'is_threat': False}
    
    def _state(self, src_ip):
        now = self.clock()
        if len(self.suspicious_ips) >= 10000:
            self.suspicious_ips = {ip: data for ip, data in self.suspicious_ips.items()
                                   if now - data['last_seen'] < self.window}
            if len(self.suspicious_ips) >= 10000 and src_ip not in self.suspicious_ips:
                self.suspicious_ips.pop(min(self.suspicious_ips,
                                           key=lambda ip: self.suspicious_ips[ip]['last_seen']))
        state = self.suspicious_ips.setdefault(src_ip, {'ports': {}, 'syn_times': deque(),
                                                       'first_seen': now, 'last_seen': now})
        state['last_seen'] = now
        return now, state

    def _detect_port_scan(self, features):
        """Count distinct destination ports in a sliding minute, not a rate
        extrapolated from the first few microseconds of a connection."""
        src_ip, port = features.get('src_ip'), features.get('dst_port')
        if not src_ip or port is None:
            return False
        now, state = self._state(src_ip)
        state['ports'] = {p: ts for p, ts in state['ports'].items() if now - ts < self.window}
        state['ports'][port] = now
        return len(state['ports']) >= self.port_scan_threshold

    def _detect_dos(self, features):
        if not features.get('src_ip') or features.get('protocol') != 6:
            return False
        flags = features.get('tcp_flags', 0)
        if not flags & 0x02 or flags & 0x10:  # count SYN, not SYN+ACK
            return False
        now, state = self._state(features['src_ip'])
        samples = state['syn_times']
        while samples and now - samples[0] >= self.window:
            samples.popleft()
        samples.append(now)
        while len(samples) > self.connection_threshold:
            samples.popleft()
        return len(samples) >= self.connection_threshold

    def _detect_suspicious_port(self, features):
        """Detect connections to suspicious ports"""
        suspicious_ports = {
            4444, 4445,  # Metasploit default
            5555, 5556,  # Common backdoors
            6666, 6667,  # IRC/Botnets
            31337,       # Back Orifice
            12345, 12346 # NetBus
        }
        
        dst_port = features.get('dst_port')
        if dst_port in suspicious_ports:
            logger.warning(f"Connection to suspicious port {dst_port}")
            return True
        
        return False
    
    def _calculate_severity(self, threats):
        """Calculate severity based on threat types"""
        severity_map = {
            'DOS_ATTACK': 1,
            'PORT_SCAN': 2,
            'SQL_INJECTION': 1,
            'BRUTE_FORCE': 2,
            'SUSPICIOUS_PORT': 3
        }
        
        min_severity = 4
        for threat in threats:
            min_severity = min(min_severity, severity_map.get(threat, 3))
        
        return min_severity
    
    def _generate_description(self, threats, features):
        """Generate human-readable description"""
        src_ip = features.get('src_ip', 'unknown')
        dst_ip = features.get('dst_ip', 'unknown')
        dst_port = features.get('dst_port', 'unknown')
        
        return f"Detected {', '.join(threats)} from {src_ip} to {dst_ip}:{dst_port}"
