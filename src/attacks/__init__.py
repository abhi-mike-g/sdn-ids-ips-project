"""
Attacks package - Attack simulation and testing

Handles:
- Attack scenario execution
- Multiple attack types
- Attack orchestration
- Demo scenarios
"""

from .attack_base import AttackBase
from .attack_manager import AttackManager
from .dos_attack import DoSAttack, UDPFloodAttack, ICMPFloodAttack
from .port_scan import PortScanAttack
from .mitm_attack import MITMAttack
from .sql_injection import SQLInjectionAttack, BlindSQLInjection
from .brute_force import BruteForceAttack

__all__ = [
    'AttackBase',
    'AttackManager',
    'DoSAttack',
    'UDPFloodAttack',
    'ICMPFloodAttack',
    'PortScanAttack',
    'MITMAttack',
    'SQLInjectionAttack',
    'BlindSQLInjection',
    'BruteForceAttack'
]
