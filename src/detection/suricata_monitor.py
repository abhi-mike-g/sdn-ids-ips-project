"""Tail EVE alerts, tolerating delayed creation, rotation and partial writes."""
import json
import threading
from orchestrator.eve_watcher import tail_alerts
from ..utils.logger import setup_logger
from ..utils.config import config

logger = setup_logger('suricata_monitor')


class SuricataMonitor:
    def __init__(self, alert_callback=None):
        self.eve_log_path = str(config.path('suricata.eve_log', '/var/log/suricata/eve.json'))
        self.alert_callback = alert_callback
        self.running = False
        self._stop = threading.Event()

    def start(self):
        if self.running:
            return
        self.running = True
        self._stop.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_log, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        self.running = False
        self._stop.set()
        if hasattr(self, '_monitor_thread'):
            self._monitor_thread.join(timeout=2)

    def _monitor_log(self):
        for alert in tail_alerts(self.eve_log_path, stop_event=self._stop):
            try:
                self._handle_alert(alert)
            except Exception:
                logger.exception('Unable to process EVE alert')

    def _process_line(self, line):
        try:
            event = json.loads(line)
            if isinstance(event, dict) and event.get('event_type') == 'alert':
                self._handle_alert(event)
        except (ValueError, TypeError):
            logger.warning('Ignoring malformed EVE record')

    def _handle_alert(self, alert):
        if self.alert_callback:
            self.alert_callback(alert)
