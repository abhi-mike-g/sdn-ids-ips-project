"""
System-level integration tests for SDN-NIDPS
"""

import unittest
import time
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

class TestSystemIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    @classmethod
    def setUpClass(cls):
        """Set up system for testing"""
        cls.project_root = Path(__file__).parent.parent
        cls.config_file = cls.project_root / 'config' / 'controller_config.json'
    
    def test_project_structure(self):
        """Test that project has correct structure"""
        required_dirs = [
            'src',
            'src/controller',
            'src/detection',
            'src/network',
            'src/database',
            'src/dashboard',
            'src/attacks',
            'src/monitoring',
            'src/utils',
            'tests',
            'docs',
            'threat_model',
            'logs',
            'models',
            'config'
        ]
        
        for dir_path in required_dirs:
            full_path = self.project_root / dir_path
            self.assertTrue(full_path.exists(), f"Missing directory: {dir_path}")
    
    def test_required_files(self):
        """Test that required files exist"""
        required_files = [
            'setup.sh',
            'requirements.txt',
            'README.md',
            'src/__init__.py',
            'src/controller/__init__.py',
            'src/detection/__init__.py',
            'config/controller_config.json',
            'docs/API_DOCS.md',
            'docs/DEPLOYMENT.md'
        ]
        
        for file_path in required_files:
            full_path = self.project_root / file_path
            self.assertTrue(full_path.exists(), f"Missing file: {file_path}")
    
    def test_imports(self):
        """Test that all modules can be imported"""
        try:
            from src.controller.sdn_controller import SDNIDPSController
            from src.detection.suricata_monitor import SuricataMonitor
            from src.database.database import DatabaseManager
            from src.attacks.attack_manager import AttackManager
            print("✓ All modules imported successfully")
        except ImportError as e:
            self.fail(f"Import error: {e}")
    
    def test_database_initialization(self):
        """Test database can be initialized"""
        try:
            from src.database.database import DatabaseManager
            db = DatabaseManager()
            self.assertIsNotNone(db)
            print("✓ Database initialized successfully")
        except Exception as e:
            self.fail(f"Database initialization failed: {e}")
    
    def test_config_loading(self):
        """Test configuration can be loaded"""
        try:
            from src.utils.config import Config
            config = Config()
            self.assertIsNotNone(config.get('controller.host'))
            self.assertIsNotNone(config.get('database.url'))
            print("✓ Configuration loaded successfully")
        except Exception as e:
            self.fail(f"Config loading failed: {e}")
    
    def test_logger_setup(self):
        """Test logger can be initialized"""
        try:
            from src.utils.logger import setup_logger
            logger = setup_logger('test')
            self.assertIsNotNone(logger)
            logger.info("Test log message")
            print("✓ Logger initialized successfully")
        except Exception as e:
            self.fail(f"Logger setup failed: {e}")
    
    def test_attack_manager(self):
        """Test attack manager initialization"""
        try:
            from src.attacks.attack_manager import AttackManager
            manager = AttackManager()
            self.assertIsNotNone(manager.attacks)
            self.assertGreater(len(manager.attacks), 0)
            print("✓ Attack manager initialized successfully")
        except Exception as e:
            self.fail(f"Attack manager initialization failed: {e}")
    
    def test_python_version(self):
        """Test Python version compatibility"""
        import sys
        version = sys.version_info
        self.assertGreaterEqual(version.major, 3, "Python 3+ required")
        self.assertGreaterEqual(version.minor, 8, "Python 3.8+ required")
        print(f"✓ Python version compatible: {version.major}.{version.minor}")
    
    def test_setup_script_exists(self):
        """Test setup script exists and is executable"""
        setup_script = self.project_root / 'setup.sh'
        self.assertTrue(setup_script.exists(), "setup.sh not found")
        
        # Check if executable
        import os
        self.assertTrue(os.access(setup_script, os.X_OK), 
                       "setup.sh is not executable")
    
    def test_requirements_format(self):
        """Test requirements.txt is properly formatted"""
        req_file = self.project_root / 'requirements.txt'
        self.assertTrue(req_file.exists(), "requirements.txt not found")
        
        with open(req_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Should contain package name and optional version
                    self.assertTrue('==' in line or len(line.split()) == 1,
                                  f"Invalid requirement: {line}")
    
    def test_documentation_exists(self):
        """Test documentation files exist"""
        doc_files = [
            'README.md',
            'docs/API_DOCS.md',
            'docs/DEPLOYMENT.md'
        ]
        
        for doc in doc_files:
            full_path = self.project_root / doc
            self.assertTrue(full_path.exists(), f"Missing documentation: {doc}")
            
            # Check file is not empty
            with open(full_path, 'r') as f:
                content = f.read()
                self.assertGreater(len(content), 100, 
                                  f"Documentation file too short: {doc}")

class TestComponentInteraction(unittest.TestCase):
    """Test interactions between components"""
    
    def test_controller_and_detector(self):
        """Test controller can work with detector"""
        from src.controller.sdn_controller import SDNIDPSController
        from src.controller.threat_detector import ThreatDetector
        
        detector = ThreatDetector()
        self.assertIsNotNone(detector)
    
    def test_database_and_alerts(self):
        """Test database can store alerts"""
        from src.database.database import DatabaseManager
        
        db = DatabaseManager()
        alert_data = {
            'severity': 1,
            'alert_type': 'TEST',
            'source_ip': '10.0.0.1',
            'destination_ip': '10.0.0.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'signature': 'Test',
            'blocked': False
        }
        
        alert_id = db.insert_alert(alert_data)
        self.assertIsNotNone(alert_id)

class TestErrorHandling(unittest.TestCase):
    """Test error handling"""
    
    def test_invalid_config(self):
        """Test handling of invalid configuration"""
        from src.utils.config import Config
        
        config = Config()
        # Should return default or None for missing keys
        value = config.get('nonexistent.key', 'default')
        self.assertEqual(value, 'default')
    
    def test_database_error_handling(self):
        """Test database error handling"""
        from src.database.database import DatabaseManager
        
        try:
            db = DatabaseManager()
            # Try to get alerts (should not raise even if DB is empty)
            alerts = db.get_recent_alerts(limit=10)
            self.assertIsNotNone(alerts)
        except Exception as e:
            self.fail(f"Database error not handled: {e}")

if __name__ == '__main__':
    unittest.main()
