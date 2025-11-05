# dashboard/app.py
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

class DashboardManager:
    def __init__(self):
        self.active_connections = 0
        self.threat_count = 0
        
    @app.route('/')
    def index():
        return render_template('dashboard.html')
    
    @app.route('/api/topology')
    def get_topology():
        """Return network topology for visualization"""
        return jsonify(topology_manager.get_topology_data())
    
    @app.route('/api/metrics')
    def get_metrics():
        """Real-time system metrics"""
        return jsonify({
            'throughput': metrics.get_throughput(),
            'latency': metrics.get_latency(),
            'active_flows': flow_manager.count_flows(),
            'threats_detected': threat_detector.count_threats(),
            'blocked_ips': policy_enforcer.count_blocked()
        })
    
    @socketio.on('connect')
    def handle_connect():
        """WebSocket connection for real-time updates"""
        emit('connection_response', {'status': 'connected'})
    
    def emit_alert(self, alert_data):
        """Push real-time alerts to dashboard"""
        socketio.emit('new_alert', alert_data)
