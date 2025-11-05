# detection/traffic_analyzer.py
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

class TrafficAnalyzer:
    """
    Analyzes traffic patterns for anomaly detection
    """
    
    def __init__(self):
        self.model = self.load_or_train_model()
        self.feature_window = []
        
    def extract_features(self, flow):
        """Extract features from network flow"""
        return {
            'packet_count': flow.packet_count,
            'byte_count': flow.byte_count,
            'duration': flow.duration,
            'packets_per_second': flow.packet_count / max(flow.duration, 1),
            'bytes_per_packet': flow.byte_count / max(flow.packet_count, 1),
            'protocol': self.encode_protocol(flow.protocol),
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'tcp_flags': flow.tcp_flags if flow.protocol == 6 else 0
        }
    
    def detect_anomaly(self, flow_features):
        """ML-based anomaly detection"""
        feature_vector = self.prepare_feature_vector(flow_features)
        prediction = self.model.predict([feature_vector])
        confidence = self.model.predict_proba([feature_vector])
        
        return {
            'is_anomaly': prediction[0] == 1,
            'confidence': confidence[0][1],
            'attack_type': self.classify_attack_type(feature_vector)
        }
    
    def load_or_train_model(self):
        """Load pre-trained model or train new one"""
        try:
            return joblib.load('models/traffic_classifier.pkl')
        except FileNotFoundError:
            # Train on CICIDS2017 dataset
            return self.train_model()
