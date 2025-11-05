import threading
import time
from ..utils.logger import setup_logger
from ..database.database import db

logger = setup_logger('network_monitor')

class NetworkMonitor:
    def __init__(self, topology_manager, interval=5):
        self.topology_manager = topology_manager
        self.interval = interval
        self.running = False
        self._monitor_thread = None
        
    def start(self):
        """Start monitoring"""
        if self.running:
            return
        
        self.running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Network monitor started")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Network monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._collect_statistics()
                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
    
    def _collect_statistics(self):
        """Collect and store network statistics"""
        stats = self.topology_manager.get_statistics()
        
        # Store in database
        # db.insert_metrics(stats)
        
        logger.debug(f"Network stats: {stats}")
