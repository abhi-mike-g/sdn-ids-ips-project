# detection/suricata_integration.py
import subprocess
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SuricataMonitor:
    def __init__(self, eve_log_path='/var/log/suricata/eve.json'):
        self.eve_log_path = eve_log_path
        self.callbacks = []
        
    def start_monitoring(self):
        """Monitor Suricata EVE JSON logs in real-time"""
        event_handler = SuricataEventHandler(self.callbacks)
        observer = Observer()
        observer.schedule(event_handler, path=self.eve_log_path, recursive=False)
        observer.start()
        
    def add_callback(self, callback):
        """Register callback for alert processing"""
        self.callbacks.append(callback)

class SuricataEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        """Process new alerts"""
        with open(event.src_path, 'r') as f:
            for line in f:
                try:
                    alert = json.loads(line)
                    if alert.get('event_type') == 'alert':
                        self._process_alert(alert)
                except json.JSONDecodeError:
                    continue
