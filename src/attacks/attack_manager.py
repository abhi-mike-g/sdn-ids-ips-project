import threading
import time
from .dos_attack import DoSAttack
from .port_scan import PortScanAttack
from .mitm_attack import MITMAttack
from .sql_injection import SQLInjectionAttack
from .brute_force import BruteForceAttack
from ..utils.logger import setup_logger

logger = setup_logger('attack_manager')

class AttackManager:
    """Orchestrates and manages attack scenarios"""
    
    def __init__(self):
        self.attacks = {
            'dos': DoSAttack,
            'port_scan': PortScanAttack,
            'mitm': MITMAttack,
            'sql_injection': SQLInjectionAttack,
            'brute_force': BruteForceAttack
        }
        self.active_attacks = {}
        self.attack_history = []
        
    def execute_attack(self, attack_type, target, **kwargs):
        """Execute specific attack"""
        if attack_type not in self.attacks:
            logger.error(f"Unknown attack type: {attack_type}")
            return None
        
        attack_class = self.attacks[attack_type]
        attack = attack_class()
        
        # Run attack in separate thread
        thread = threading.Thread(
            target=self._run_attack,
            args=(attack, target),
            kwargs=kwargs,
            daemon=True
        )
        thread.start()
        
        attack_id = f"{attack_type}_{int(time.time())}"
        self.active_attacks[attack_id] = {
            'attack': attack,
            'thread': thread,
            'target': target
        }
        
        logger.info(f"Attack launched: {attack_type} -> {target}")
        return attack_id
    
    def _run_attack(self, attack, target, **kwargs):
        """Run attack with error handling"""
        try:
            attack.start()
            result = attack.execute(target, **kwargs)
            attack.stop()
            
            self.attack_history.append(attack.get_report())
            
        except Exception as e:
            logger.error(f"Attack failed: {e}")
            attack.status = 'failed'
    
    def stop_attack(self, attack_id):
        """Stop running attack"""
        if attack_id in self.active_attacks:
            attack_info = self.active_attacks[attack_id]
            attack_info['attack'].stop()
            del self.active_attacks[attack_id]
            logger.info(f"Attack stopped: {attack_id}")
    
    def get_attack_status(self, attack_id):
        """Get attack status"""
        if attack_id in self.active_attacks:
            return self.active_attacks[attack_id]['attack'].status
        return None
    
    def run_demo_scenario(self, target='10.0.0.2'):
        """Run complete demo scenario"""
        logger.info("Starting demo attack scenario")
        
        demo_attacks = [
            ('port_scan', {'ports': '1-1024', 'delay': 0.1}),
            ('dos', {'duration': 30, 'packet_rate': 100}),
            ('brute_force', {'service': 'ssh', 'attempts': 50}),
            ('sql_injection', {'url': f'http://{target}/login'}),
        ]
        
        for attack_type, kwargs in demo_attacks:
            logger.info(f"Executing: {attack_type}")
            attack_id = self.execute_attack(attack_type, target, **kwargs)
            time.sleep(10)  # Wait between attacks
        
        logger.info("Demo scenario completed")
    
    def get_statistics(self):
        """Get attack statistics"""
        return {
            'active_attacks': len(self.active_attacks),
            'total_attacks': len(self.attack_history),
            'attack_types': list(self.attacks.keys())
        }
