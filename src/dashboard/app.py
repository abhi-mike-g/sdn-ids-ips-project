"""Dashboard entry point: python -m src.dashboard.app."""
import os
import threading
from flask import Flask, render_template
from .api import api_bp, proxy_incidents, serialize_alert
from .clients import ServiceClient, ServiceUnavailable
from .websocket import socketio
from ..database.database import db
from ..monitoring.metrics_collector import MetricsCollector
from ..utils.config import config


def create_app(database=None, controller_client=None, incident_store=None, orchestrator=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('NIDPS_SECRET_KEY') or os.urandom(32),
                      NIDPS_MODE='offline replay' if incident_store else 'live')
    app.extensions['nidps_db'] = database or db
    app.extensions['incident_store'] = incident_store
    app.extensions['controller_client'] = controller_client or ServiceClient(
        config.get('controller.api_url', 'http://127.0.0.1:8080'))
    app.extensions['incident_client'] = ServiceClient(
        config.get('orchestrator.api_url', 'http://127.0.0.1:5001'))
    app.extensions['metrics_collector'] = MetricsCollector(database=database or db)
    socketio.init_app(app, async_mode='threading')
    app.register_blueprint(api_bp, url_prefix='/api')
    if incident_store is not None:
        from orchestrator.api import register_routes
        register_routes(app, incident_store, orchestrator)
    else:
        app.add_url_rule('/api/incidents', 'incidents_proxy',
                         lambda: proxy_incidents('incidents'))
        app.add_url_rule('/api/stats', 'incident_stats_proxy', lambda: proxy_incidents('stats'))
        app.add_url_rule('/api/incidents/<path:path>', 'incident_proxy',
                         lambda path: proxy_incidents('incidents/' + path), methods=['GET', 'POST'])

    for path, template in [('/', 'dashboard'), ('/topology', 'topology'),
                           ('/logs', 'logs'), ('/metrics', 'metrics'), ('/incidents', 'incidents'),
                           ('/briefing', 'briefing')]:
        app.add_url_rule(path, 'page_' + template,
                         lambda template=template: render_template(template + '.html'))
    return app


class DashboardFeed:
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.database = app.extensions['nidps_db']
        self.cursor = self.database.latest_alert_id()

    def tick(self):
        collector = self.app.extensions['metrics_collector']
        metrics = collector.collect_metrics()
        collector._store_metrics(metrics)
        socketio.emit('metrics_update', metrics)
        for alert in self.database.get_recent_alerts(limit=1000, after_id=self.cursor):
            socketio.emit('new_alert', serialize_alert(alert))
            self.cursor = alert.id
        try:
            topology = self.app.extensions.get('demo_topology')
            if topology is None:
                topology = self.app.extensions['controller_client'].get('/nidps/topology')
            socketio.emit('topology_update', topology)
        except ServiceUnavailable:
            pass
        socketio.emit('statistics_update', self.database.statistics())

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                self.app.logger.exception('Dashboard update failed')
            self.stop_event.wait(config.get('monitoring.metrics_interval', 5))


def run_dashboard(app=None):
    app = app or create_app()
    feed = DashboardFeed(app)
    thread = threading.Thread(target=feed.run, daemon=True)
    thread.start()
    try:
        socketio.run(app, host=config.get('dashboard.host', '127.0.0.1'),
                     port=config.get('dashboard.port', 5000), debug=False,
                     allow_unsafe_werkzeug=True, use_reloader=False)
    finally:
        feed.stop_event.set()
        thread.join(timeout=5)


if __name__ == '__main__':
    run_dashboard()
