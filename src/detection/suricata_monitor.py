import json
import threading
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ..utils.logger import setup_logger
from ..utils.config import config

logger = setup_logger('suricata_monitor')

class SuricataMonitor:
    def __init__(self, alert_callback=None):
        self.eve_log_path = config.get('suricata.eve_log', '/var/log/suricata/eve.json')
        self.alert_callback = alert_callback
        self.observer = None
        self.running = False
        self._last_position = 0
        
    def start(self):
        """Start monitoring Suricata EVE log"""
        if self.running:
            logger.warning("Suricata monitor already running")
            return
        
        eve_log = Path(self.eve_log_path)
        if not eve_log.exists():
            logger.error(f"Suricata EVE log not found: {self.eve_log_path}")
            return
        
        self.running = True
        self._monitor_thread = threading.Thread(target=self._monitor_log, daemon=True)
        self._monitor_thread.start()
        
        logger.info(f"Suricata monitor started: {self.eve_log_path}")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
        logger.info("Suricata monitor stopped")
    
    def _monitor_log(self):
        """Monitor log file for new entries"""
        with open(self.eve_log_path, 'r') as f:
            # Seek to end if not starting fresh
            if self._last_position > 0:
                f.seek(self._last_position)
            else:
                f.seek(0, 2)  # Go to end
            
            while self.running:
                line = f.readline()
                if line:
                    self._process_line(line)
                    self._last_position = f.tell()
                else:
                    time.sleep(0.1)  # Wait for new data
    
    def _process_line(self, line):
        """Process a single log line"""
        try:
            event = json.loads(line.strip())
            event_type = event.get('event_type')
            
            if event_type == 'alert':
                self._handle_alert(event)
            elif event_type == 'flow':
                self._handle_flow(event)
            elif event_type == 'stats':
                self._handle_stats(event)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Suricata log: {e}")
    
    def _handle_alert(self, alert):
        """Handle Suricata alert"""
        logger.warning(f"Suricata Alert: {alert.get('alert', {}).get('signature')}")
        
        if self.alert_callback:
            self.alert_callback(alert)
    
    def _handle_flow(self, flow):
        """Handle flow event"""
        # Can be used for flow-based analysis
        pass
    
    def _handle_stats(self, stats):
        """Handle statistics event"""
        # Can be used for performance monitoring
        pass

class SuricataEventHandler(FileSystemEventHandler):
    """Alternative: Use watchdog for file monitoring"""
    
    def __init__(self, callback):
        self.callback = callback
        self.file_handle = None
        
    def on_modified(self, event):
        if event.src_path.endswith('eve.json'):
            # Read new lines
            pass
