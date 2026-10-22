import numpy as np
import joblib
from pathlib import Path
from ..utils.logger import setup_logger
from ..utils.config import config

logger = setup_logger('ml_detector')

class MLDetector:
    def __init__(self):
        self.model = None
        self.feature_names = [
            'packet_count', 'byte_count', 'duration', 
            'packets_per_second', 'bytes_per_packet',
            'protocol', 'src_port', 'dst_port', 'tcp_flags'
        ]
        self.attack_types = [
            'BENIGN', 'DOS', 'PROBE', 'R2L', 'U2R'
        ]
        if config.get('detection.enable_ml', True):
            self._load_model()
    
    def _load_model(self):
        """Load pre-trained ML model"""
        model_path = config.path('detection.model_path', 'models/traffic_classifier.pkl')
        
        if model_path.exists():
            try:
                self.model = joblib.load(model_path)
                from sklearn.pipeline import Pipeline
                if not isinstance(self.model, Pipeline):
                    scaler_path = model_path.parent / 'scaler.pkl'
                    if not scaler_path.exists():
                        raise ValueError('Legacy model has no scaler; run models/setup_model.py')
                    self.model = Pipeline([('scale', joblib.load(scaler_path)), ('classifier', self.model)])
                logger.info(f"ML model loaded: {model_path}")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
                self.model = None
        else:
            logger.warning(f"ML model not found: {model_path}")
            logger.info("ML-based detection disabled")
    
    def is_loaded(self):
        """Check if model is loaded"""
        return self.model is not None
    
    def predict(self, flow_features):
        """Predict if flow is malicious"""
        if not self.is_loaded():
            return {'is_malicious': False, 'confidence': 0.0}
        
        try:
            # Extract and normalize features
            feature_vector = self._extract_features(flow_features)
            
            # Make prediction
            prediction = self.model.predict([feature_vector])[0]
            probabilities = self.model.predict_proba([feature_vector])[0]
            
            prediction = int(prediction)
            labels = [int(label) for label in self.model.classes_]
            attack_type = self.attack_types[prediction]
            confidence = probabilities[labels.index(prediction)]
            
            threshold = config.get('detection.threshold', 0.7)
            
            return {
                'is_malicious': attack_type != 'BENIGN' and confidence > threshold,
                'attack_type': attack_type,
                'confidence': float(confidence),
                'probabilities': {
                    self.attack_types[label]: float(probabilities[i])
                    for i, label in enumerate(labels)
                }
            }
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return {'is_malicious': False, 'confidence': 0.0}
    
    def _extract_features(self, flow_features):
        """Extract and normalize features for ML model"""
        features = []
        
        # Extract numerical features
        features.append(flow_features.get('packet_count', 0))
        features.append(flow_features.get('byte_count', 0))
        features.append(flow_features.get('duration', 0))
        
        # Calculate derived features
        duration = max(flow_features.get('duration', 1), 0.001)
        packet_count = max(flow_features.get('packet_count', 1), 1)
        
        features.append(flow_features.get('packet_count', 0) / duration)  # pps
        features.append(flow_features.get('byte_count', 0) / packet_count)  # bpp
        
        # Protocol features
        features.append(flow_features.get('protocol', 0))
        features.append(flow_features.get('src_port', 0))
        features.append(flow_features.get('dst_port', 0))
        features.append(flow_features.get('tcp_flags', 0))
        
        return np.array(features)
    
    def train_model(self, training_data, labels):
        from models.train_models import ModelTrainer
        trainer = ModelTrainer(config.path('detection.model_path', 'models/traffic_classifier.pkl'))
        trainer.source = 'caller supplied data'
        trainer.train(training_data, labels)
        trainer.save_model()
        self.model = trainer.model
