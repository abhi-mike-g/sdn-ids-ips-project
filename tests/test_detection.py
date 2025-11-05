import unittest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime, timedelta

class TestThreatDetection(unittest.TestCase):
    """Test threat detection components"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': 1,
            'alert_type': 'PORT_SCAN',
            'source_ip': '10.0.0.1',
            'destination_ip': '10.0.0.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'signature': 'Test Signature'
        }
    
    def test_suricata_monitor_initialization(self):
        """Test Suricata monitor initialization"""
        from src.detection.suricata_monitor import SuricataMonitor
        
        monitor = SuricataMonitor()
        self.assertIsNotNone(monitor)
        self.assertEqual(monitor.running, False)
    
    def test_traffic_analyzer_flow_analysis(self):
        """Test traffic flow analysis"""
        from src.detection.traffic_analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        
        flow_features = {
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'dst_port': 80,
            'packet_count': 100,
            'byte_count': 50000,
            'duration': 10,
            'protocol': 6,
            'total_length': 1500
        }
        
        result = analyzer.analyze_flow(flow_features)
        
        self.assertIsNotNone(result)
        self.assertIn('has_anomaly', result)
        self.assertIn('anomalies', result)
        self.assertIn('confidence', result)
    
    def test_port_scan_detection(self):
        """Test port scanning detection"""
        from src.detection.traffic_analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        
        # Simulate port scan
        for port in range(1, 11):
            flow_features = {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'dst_port': port,
                'packet_count': 1,
                'byte_count': 60,
                'duration': 1,
                'protocol': 6,
                'total_length': 60
            }
            analyzer.analyze_flow(flow_features)
        
        # Should detect anomaly
        self.assertTrue(len(analyzer.flow_cache) > 0)
    
    def test_ml_detector_prediction(self):
        """Test ML-based detection"""
        from src.detection.ml_detector import MLDetector
        
        detector = MLDetector()
        
        flow_features = {
            'packet_count': 100,
            'byte_count': 50000,
            'duration': 10,
            'protocol': 6,
            'src_port': 12345,
            'dst_port': 80,
            'tcp_flags': 0
        }
        
        result = detector.predict(flow_features)
        
        self.assertIsNotNone(result)
        self.assertIn('is_malicious', result)
        self.assertIn('confidence', result)
    
    def test_threat_detector_port_scan(self):
        """Test threat detector port scan detection"""
        from src.controller.threat_detector import ThreatDetector
        
        detector = ThreatDetector()
        
        # Simulate port scan
        for port in range(1, 50):
            features = {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'dst_port': port,
                'protocol': 6,
                'tcp_flags': 0x02,
                'total_length': 60,
                'ttl': 64
            }
            
            result = detector.analyze_packet(features)
        
        # Should eventually detect threat
        self.assertIn('suspicious_ips', vars(detector))
    
    def test_threat_detector_dos(self):
        """Test DoS attack detection"""
        from src.controller.threat_detector import ThreatDetector
        
        detector = ThreatDetector()
        
        # Simulate SYN flood
        for i in range(150):
            features = {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'dst_port': 80,
                'protocol': 6,
                'tcp_flags': 0x02,  # SYN flag
                'total_length': 60
            }
            
            result = detector.analyze_packet(features)
    
    def test_threat_detector_suspicious_port(self):
        """Test suspicious port detection"""
        from src.controller.threat_detector import ThreatDetector
        
        detector = ThreatDetector()
        
        suspicious_features = {
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'dst_port': 31337,  # Back Orifice
            'protocol': 6
        }
        
        result = detector.analyze_packet(suspicious_features)
        
        # Should detect suspicious port
        self.assertTrue(detector._detect_suspicious_port(suspicious_features))

class TestDatabase(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        """Set up test database"""
        from src.database.database import DatabaseManager
        
        # Use in-memory SQLite for testing
        self.db = DatabaseManager()
    
    def test_insert_alert(self):
        """Test inserting alert"""
        alert_data = {
            'severity': 1,
            'alert_type': 'TEST_ALERT',
            'source_ip': '10.0.0.1',
            'destination_ip': '10.0.0.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'signature': 'Test Signature',
            'description': 'Test Description',
            'blocked': False
        }
        
        alert_id = self.db.insert_alert(alert_data)
        self.assertIsNotNone(alert_id)
    
    def test_get_recent_alerts(self):
        """Test retrieving recent alerts"""
        alert_data = {
            'severity': 1,
            'alert_type': 'TEST_ALERT',
            'source_ip': '10.0.0.1',
            'destination_ip': '10.0.0.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'signature': 'Test',
            'blocked': False
        }
        
        self.db.insert_alert(alert_data)
        alerts = self.db.get_recent_alerts(limit=10)
        
        self.assertIsNotNone(alerts)

class TestAttackDetection(unittest.TestCase):
    """Test attack detection"""
    
    def test_detect_port_scan_signature(self):
        """Test port scan detection signature"""
        # Verify Suricata rule exists
        with open('src/detection/rules/custom.rules', 'r') as f:
            rules = f.read()
            self.assertIn('Port Scan Detected', rules)
    
    def test_detect_dos_signature(self):
        """Test DoS detection signature"""
        with open('src/detection/rules/custom.rules', 'r') as f:
            rules = f.read()
            self.assertIn('SYN Flood Attack', rules)
    
    def test_detect_sql_injection_signature(self):
        """Test SQL injection detection"""
        with open('src/detection/rules/custom.rules', 'r') as f:
            rules = f.read()
            self.assertIn('SQL Injection', rules)
    
    def test_detect_xss_signature(self):
        """Test XSS detection"""
        with open('src/detection/rules/custom.rules', 'r') as f:
            rules = f.read()
            self.assertIn('XSS Attempt', rules)

if __name__ == '__main__':
    unittest.main()
