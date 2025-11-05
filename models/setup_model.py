"""
Model setup helper - Downloads or generates ML model if not present
"""

import os
from pathlib import Path
import sys

def setup_model():
    """
    Setup ML model for anomaly detection
    If model doesn't exist, generate synthetic training data and train it
    """
    
    model_path = Path(__file__).parent / 'traffic_classifier.pkl'
    
    # Check if model exists
    if model_path.exists():
        print(f"✓ Model exists: {model_path}")
        return True
    
    print("⚠ ML model not found. Generating...")
    
    # Try to train model
    try:
        # Add parent directory to path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        from models.train_model import ModelTrainer
        
        print("Starting model training...")
        trainer = ModelTrainer()
        
        # Generate synthetic data
        X, y = trainer.generate_synthetic_data(n_samples=10000)
        
        # Train model
        trainer.train(X, y)
        
        # Save model
        trainer.save_model()
        
        print("✓ Model trained and saved successfully")
        return True
        
    except Exception as e:
        print(f"✗ Failed to train model: {e}")
        print("\nTo manually train the model, run:")
        print("  python3 models/train_model.py --synthetic --samples 10000")
        return False

if __name__ == '__main__':
    setup_model()
