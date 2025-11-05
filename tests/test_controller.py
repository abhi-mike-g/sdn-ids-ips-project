import unittest
from unittest.mock import Mock, patch, MagicMock
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER

class TestSDNController(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.mock_datapath = Mock()
        self.mock_datapath.id = 1
        self.mock_datapath.ofproto = ofproto_v1_3
        self.mock_datapath.ofproto_parser = Mock()
    
    def test_flow_manager_install_flow(self):
        """Test flow installation"""
        from src.controller.flow_manager import FlowManager
        
        manager = FlowManager()
        match = self.mock_datapath.ofproto_parser.OFPMatch()
        actions = []
        
        # Mock send_msg
        self.mock_datapath.send_msg = Mock()
        
        flow_id = manager.install_flow(
            self.mock_datapath,
            priority=100,
            match=match,
            actions=actions
        )
        
        self.assertIsNotNone(flow_id)
        self.assertTrue(self.mock_datapath.send_msg.called)
    
    def test_threat_detector_port_scan(self):
        """Test port scan detection"""
        from src.controller.threat_detector import ThreatDetector
        
        detector = ThreatDetector()
        
        # Simulate multiple port scans
        for port in range(1, 100):
            features = {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'dst_port': port,
                'protocol': 6
            }
            result = detector._detect_port_scan(features)
        
        # Should detect after threshold
        self.assertTrue(result or len(detector.suspicious_ips) > 0)
    
    def test_policy_enforcer_block_ip(self):
        """Test IP blocking"""
        from src.controller.policy_enforcer import PolicyEnforcer
        from src.controller.flow_manager import FlowManager
        
        flow_manager = FlowManager()
        enforcer = PolicyEnforcer(flow_manager)
        
        # Mock datapath
        self.mock_datapath.send_msg = Mock()
        
        enforcer.block_ip(self.mock_datapath, '10.0.0.1', duration=300)
        
        self.assertIn('10.0.0.1', enforcer.blocked_ips)
        self.assertTrue(self.mock_datapath.send_msg.called)

class TestThreatDetection(unittest.TestCase):
    def test_ml_detector_load(self):
        """Test ML detector initialization"""
        from src.detection.ml_detector import MLDetector
        
        detector = MLDetector()
        self.assertIsNotNone(detector)
    
    def test_traffic_analyzer(self):
        """Test traffic analysis"""
        from src.detection.traffic_analyzer import TrafficAnalyzer
        
        analyzer = TrafficAnalyzer()
        
        flow_features = {
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'dst_port': 80,
            'packet_count': 100,
            'byte_count': 5000,
            'duration': 10,
            'protocol': 6
        }
        
        result = analyzer.analyze_flow(flow_features)
        self.assertIsNotNone(result)
        self.assertIn('has_anomaly', result)

if __name__ == '__main__':
    unittest.main()
