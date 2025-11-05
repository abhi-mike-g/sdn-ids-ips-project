"""
SDN-NIDPS - Software Defined Network based Intrusion Detection & Prevention System

A comprehensive cybersecurity system combining SDN with threat modeling and
real-time intrusion detection/prevention capabilities.

Author: Abhidutta Mukund Giri, Avishi Bansal, Piyush
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Abhidutta Mukund Giri, Avishi Bansal, Piyush"
__license__ = "Educational Use"

# Import main components for easy access
try:
    from src.controller.sdn_controller import SDNIDPSController
    from src.detection.suricata_monitor import SuricataMonitor
    from src.dashboard.app import create_app
    from src.database.database import db
except ImportError as e:
    print(f"Warning: Could not import some modules: {e}")

__all__ = [
    'SDNIDPSController',
    'SuricataMonitor',
    'create_app',
    'db'
]
