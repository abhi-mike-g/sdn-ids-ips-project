"""Train a reproducible demonstration model, or a CSV with the declared schema.
Synthetic accuracy is a training smoke test, not measured IDS effectiveness.
"""
import argparse
import csv
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

FEATURES = ['packet_count', 'byte_count', 'duration', 'packets_per_second',
            'bytes_per_packet', 'protocol', 'src_port', 'dst_port', 'tcp_flags']
CLASSES = ['BENIGN', 'DOS', 'PROBE', 'R2L', 'U2R']


class ModelTrainer:
    def __init__(self, model_path='models/traffic_classifier.pkl'):
        self.model_path = Path(model_path)
        self.model = None
        self.feature_names = FEATURES
        self.attack_types = CLASSES
        self.source = 'untrained'

    def generate_synthetic_data(self, n_samples=10000):
        if n_samples < 100:
            raise ValueError('At least 100 samples required')
        rng = np.random.default_rng(42)
        y = np.arange(n_samples) % 5
        rng.shuffle(y)
        duration = rng.uniform(1, 30, n_samples)
        packets = rng.integers(5, 100, n_samples).astype(float)
        packets[y == 1] = rng.integers(500, 2000, np.sum(y == 1))
        packets[y == 2] = rng.integers(1, 5, np.sum(y == 2))
        sizes = rng.uniform(60, 1400, n_samples)
        byte_count = packets * sizes
        dport = rng.integers(1, 1024, n_samples)
        dport[y == 3] = 22
        dport[y == 4] = 4444
        flags = np.where(np.isin(y, [1, 2, 3]), 2, 16)
        X = np.column_stack([packets, byte_count, duration, packets / duration, sizes,
                             np.full(n_samples, 6), rng.integers(1024, 65535, n_samples), dport, flags])
        self.source = 'synthetic demonstration data'
        return X, y

    def load_cicids_data(self, csv_file):
        # Require a deliberate feature conversion instead of silently accepting
        # arbitrary dataset columns or treating unknown attacks as benign.
        with open(csv_file, newline='') as stream:
            rows = list(csv.DictReader(stream))
        if not rows or not set(FEATURES + ['Label']).issubset(rows[0]):
            raise ValueError('Convert CSV to the nine documented feature columns plus Label first')
        X = np.array([[float(row[name]) for name in FEATURES] for row in rows])
        y = np.array([CLASSES.index(row['Label']) for row in rows])
        self.source = str(csv_file)
        return X, y

    def train(self, X, y, test_size=0.2, random_state=42):
        if X.shape[1] != len(FEATURES) or not np.isfinite(X).all():
            raise ValueError('Nine finite features are required')
        train_x, test_x, train_y, test_y = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y)
        self.model = Pipeline([('scale', StandardScaler()),
                               ('classifier', RandomForestClassifier(n_estimators=60, max_depth=16,
                                                                      random_state=random_state, n_jobs=1))])
        self.model.fit(train_x, train_y)
        self.model.nidps_feature_names_ = FEATURES
        self.model.nidps_training_source_ = self.source
        accuracy = accuracy_score(test_y, self.model.predict(test_x))
        print(f'Validation accuracy on {self.source}: {accuracy:.4f}')
        return self.model, accuracy

    def save_model(self):
        if self.model is None:
            raise RuntimeError('Train the model first')
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f'Saved model and preprocessing together: {self.model_path}')

    def load_model(self):
        if not self.model_path.exists():
            return False
        self.model = joblib.load(self.model_path)
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data')
    parser.add_argument('--synthetic', action='store_true')
    parser.add_argument('--samples', type=int, default=10000)
    parser.add_argument('--output', default='models/traffic_classifier.pkl')
    args = parser.parse_args()
    trainer = ModelTrainer(args.output)
    X, y = trainer.load_cicids_data(args.data) if args.data else trainer.generate_synthetic_data(args.samples)
    trainer.train(X, y)
    trainer.save_model()


if __name__ == '__main__':
    main()
