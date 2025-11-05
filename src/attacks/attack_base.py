from abc import ABC, abstractmethod
from ..utils.logger import setup_logger
import time

logger = setup_logger('attack_base')

class AttackBase(ABC):
    """Base class for all attack scenarios"""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.start_time = None
        self.end_time = None
        self.status = 'initialized'
        
    @abstractmethod
    def execute(self, target, **kwargs):
        """Execute the attack"""
        pass
    
    def start(self):
        """Mark attack as started"""
        self.start_time = time.time()
        self.status = 'running'
        logger.info(f"Attack started: {self.name}")
    
    def stop(self):
        """Mark attack as stopped"""
        self.end_time = time.time()
        self.status = 'completed'
        duration = self.end_time - self.start_time
        logger.info(f"Attack completed: {self.name} (duration: {duration:.2f}s)")
    
    def get_report(self):
        """Get attack report"""
        return {
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.end_time - self.start_time if self.end_time else None
        }
