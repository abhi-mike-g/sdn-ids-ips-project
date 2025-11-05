from ..utils.logger import setup_logger
from ..detection.ml_detector import MLDetector
import time

logger = setup_logger('threat_detector')

class ThreatDetector:
    def __init__(self):
        self.ml_detector = MLDetector()
        self.suspicious_ips = {}  # {ip: {'count': int, 'first_seen': timestamp}}
        self.port_scan_threshold = 10  # ports scanned per minute
        self.connection_threshold = 100  # connections per minute
        
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
        if self.ml_detector.is_loaded():
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
    
    def _detect_port_scan(self, features):
        """Detect port scanning behavior"""
        src_ip = features.get('src_ip')
        dst_port = features.get('dst_port')
        
        if not src_ip or not dst_port:
            return False
        
        current_time = time.time()
        
        if src_ip not in self.suspicious_ips:
            self.suspicious_ips[src_ip] = {
                'ports': set(),
                'first_seen': current_time
            }
        
        ip_data = self.suspicious_ips[src_ip]
        ip_data['ports'].add(dst_port)
        
        # Check if scanning multiple ports
        time_window = current_time - ip_data['first_seen']
        if time_window > 0:
            ports_per_minute = len(ip_data['ports']) / (time_window / 60)
            if ports_per_minute > self.port_scan_threshold:
                logger.warning(f"Port scan detected from {src_ip}: {len(ip_data['ports'])} ports")
                return True
        
        # Cleanup old entries
        if time_window > 300:  # 5 minutes
            del self.suspicious_ips[src_ip]
        
        return False
    
    def _detect_dos(self, features):
        """Detect DoS attack patterns"""
        src_ip = features.get('src_ip')
        if not src_ip:
            return False
        
        # Check for SYN flood (TCP with SYN flag)
        if features.get('protocol') == 6:  # TCP
            tcp_flags = features.get('tcp_flags', 0)
            if tcp_flags & 0x02:  # SYN flag
                # Track SYN packets per IP
                if src_ip not in self.suspicious_ips:
                    self.suspicious_ips[src_ip] = {
                        'syn_count': 0,
                        'syn_first_seen': time.time()
                    }
                
                ip_data = self.suspicious_ips[src_ip]
                ip_data['syn_count'] = ip_data.get('syn_count', 0) + 1
                
                time_window = time.time() - ip_data.get('syn_first_seen', time.time())
                if time_window > 0:
                    syn_per_minute = ip_data['syn_count'] / (time_window / 60)
                    if syn_per_minute > self.connection_threshold:
                        logger.warning(f"SYN flood detected from {src_ip}")
                        return True
        
        return False
    
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
