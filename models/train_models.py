"""
Machine Learning Model Training Script

Trains a Random Forest classifier for network traffic anomaly detection
using the CICIDS2017 dataset or synthetic data.
"""

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings

warnings.filterwarnings('ignore')

class ModelTrainer:
    def __init__(self, model_path='models/traffic_classifier.pkl'):
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.feature_names = [
            'packet_count', 'byte_count', 'duration',
            'packets_per_second', 'bytes_per_packet',
            'protocol', 'src_port', 'dst_port', 'tcp_flags'
        ]
        self.attack_types = ['BENIGN', 'DOS', 'PROBE', 'R2L', 'U2R']
    
    def generate_synthetic_data(self, n_samples=10000):
        """Generate synthetic training data"""
        print("Generating synthetic training data...")
        
        X = []
        y = []
        
        for i in range(n_samples):
            # Benign traffic (80%)
            if np.random.random() < 0.8:
                sample = [
                    np.random.normal(50, 20),      # packet_count
                    np.random.normal(5000, 2000),  # byte_count
                    np.random.normal(10, 3),       # duration
                    np.random.normal(5, 2),        # packets_per_second
                    np.random.normal(100, 30),     # bytes_per_packet
                    np.random.choice([6, 17, 1]),  # protocol (TCP, UDP, ICMP)
                    np.random.randint(1024, 65535),# src_port
                    np.random.randint(1, 1024),    # dst_port
                    0                              # tcp_flags
                ]
                y.append(0)  # BENIGN
            
            # DoS attack (10%)
            elif np.random.random() < 0.125:
                sample = [
                    np.random.normal(1000, 200),   # High packet count
                    np.random.normal(50000, 10000),# High bytes
                    np.random.normal(30, 5),       # Longer duration
                    np.random.normal(100, 20),     # High rate
                    np.random.normal(50, 10),
                    6,                             # TCP
                    np.random.randint(1024, 65535),
                    np.random.randint(1, 1024),
                    0x02                           # SYN flag
                ]
                y.append(1)  # DOS
            
            # Port scanning (5%)
            elif np.random.random() < 0.0625:
                sample = [
                    np.random.normal(10, 5),       # Few packets per connection
                    np.random.normal(100, 50),     # Small data
                    np.random.normal(1, 0.5),      # Quick connections
                    np.random.normal(10, 3),
                    np.random.normal(50, 20),
                    6,                             # TCP
                    np.random.randint(1024, 65535),
                    np.random.randint(1, 1024),
                    0x02
                ]
                y.append(2)  # PROBE
            
            # Remote to local (3%)
            elif np.random.random() < 0.0375:
                sample = [
                    np.random.normal(100, 30),
                    np.random.normal(5000, 1500),
                    np.random.normal(5, 2),
                    np.random.normal(20, 5),
                    np.random.normal(80, 20),
                    6,                             # TCP
                    np.random.randint(1024, 65535),
                    np.random.choice([22, 23, 25, 110, 143]),  # Common services
                    0x02
                ]
                y.append(3)  # R2L
            
            # User to root (2%)
            else:
                sample = [
                    np.random.normal(200, 50),
                    np.random.normal(10000, 3000),
                    np.random.normal(15, 4),
                    np.random.normal(30, 8),
                    np.random.normal(100, 30),
                    6,                             # TCP
                    np.random.randint(1024, 65535),
                    np.random.randint(1, 1024),
                    0x18                           # PSH+ACK
                ]
                y.append(4)  # U2R
            
            X.append(sample)
        
        X = np.array(X)
        y = np.array(y)
        
        print(f"Generated {len(X)} samples")
        print(f"Class distribution:")
        for i, attack_type in enumerate(self.attack_types):
            count = np.sum(y == i)
            print(f"  {attack_type}: {count} ({100*count/len(y):.1f}%)")
        
        return X, y
    
    def load_cicids_data(self, csv_file):
        """Load CICIDS2017 dataset"""
        print(f"Loading CICIDS2017 data from {csv_file}...")
        
        df = pd.read_csv(csv_file)
        
        # Map labels to attack types
        label_map = {
            'BENIGN': 0,
            'DoS': 1,
            'PortScan': 2,
            'FTP-Patator': 3,
            'SSH-Patator': 3,
            'Infiltration': 3
        }
        
        # Select features
        feature_cols = [col for col in df.columns if col != 'Label']
        X = df[feature_cols].fillna(0).values
        y = df['Label'].map(label_map).fillna(0).values.astype(int)
        
        print(f"Loaded {len(X)} samples with {X.shape[1]} features")
        
        return X, y
    
    def train(self, X, y, test_size=0.2, random_state=42):
        """Train the Random Forest model"""
        print("\nTraining Random Forest model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1,
            verbose=1
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        print("\nModel Evaluation:")
        y_pred = self.model.predict(X_test_scaled)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {accuracy:.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                  target_names=self.attack_types[:len(np.unique(y_test))]))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        # Feature importance
        print("\nFeature Importance:")
        importances = self.model.feature_importances_
        for name, importance in zip(self.feature_names, importances):
            print(f"  {name}: {importance:.4f}")
        
        return self.model, accuracy
    
    def save_model(self):
        """Save trained model to disk"""
        if self.model is None:
            print("Error: Model not trained yet")
            return
        
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save model
        joblib.dump(self.model, self.model_path)
        print(f"Model saved to {self.model_path}")
        
        # Save scaler
        scaler_path = self.model_path.parent / 'scaler.pkl'
        joblib.dump(self.scaler, scaler_path)
        print(f"Scaler saved to {scaler_path}")
    
    def load_model(self):
        """Load pre-trained model"""
        if not self.model_path.exists():
            print(f"Model file not found: {self.model_path}")
            return False
        
        self.model = joblib.load(self.model_path)
        
        scaler_path = self.model_path.parent / 'scaler.pkl'
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)
        
        print(f"Model loaded from {self.model_path}")
        return True

def main():
    """Main training script"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train ML model for traffic detection')
    parser.add_argument('--data', type=str, help='Path to CICIDS2017 CSV file')
    parser.add_argument('--synthetic', action='store_true', 
                       help='Use synthetic data instead of real data')
    parser.add_argument('--samples', type=int, default=10000,
                       help='Number of synthetic samples')
    parser.add_argument('--output', type=str, default='models/traffic_classifier.pkl',
                       help='Output model path')
    
    args = parser.parse_args()
    
    trainer = ModelTrainer(model_path=args.output)
    
    # Load or generate training data
    if args.data and Path(args.data).exists():
        X, y = trainer.load_cicids_data(args.data)
    else:
        print("Using synthetic data...")
        X, y = trainer.generate_synthetic_data(n_samples=args.samples)
    
    # Train model
    trainer.train(X, y)
    
    # Save model
    trainer.save_model()
    
    print("\nTraining completed successfully!")

if __name__ == '__main__':
    main()
