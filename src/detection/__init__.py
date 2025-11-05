"""
Detection package - Threat detection engines

Handles:
- Suricata IDS integration
- Machine learning based detection
- Traffic analysis
- Real-time threat identification
"""

from .suricata_monitor import SuricataMonitor
from .traffic_analyzer import TrafficAnalyzer
from .ml_detector import MLDetector

__all__ = [
    'SuricataMonitor',
    'TrafficAnalyzer',
    'MLDetector'
]
