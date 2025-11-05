import json
import os
from pathlib import Path

class Config:
    def __init__(self, config_file='config/controller_config.json'):
        self.config_file = Path(config_file)
        self._config = self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return self._default_config()
    
    def _default_config(self):
        """Default configuration"""
        return {
            'controller': {
                'host': '0.0.0.0',
                'port': 6653,
                'wsgi_port': 8080
            },
            'database': {
                'url': 'sqlite:///logs/nidps.db'
            },
            'suricata': {
                'eve_log': '/var/log/suricata/eve.json',
                'rules_path': '/etc/suricata/rules'
            },
            'dashboard': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': True
            },
            'detection': {
                'enable_ml': True,
                'model_path': 'models/traffic_classifier.pkl',
                'threshold': 0.7
            },
            'monitoring': {
                'metrics_interval': 5,
                'enable_prometheus': False
            }
        }
    
    def get(self, key, default=None):
        """Get config value using dot notation"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default
    
    def save(self):
        """Save configuration to file"""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self._config, f, indent=4)

# Singleton
config = Config()
