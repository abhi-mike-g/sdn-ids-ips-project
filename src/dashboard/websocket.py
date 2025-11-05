from flask_socketio import SocketIO, emit
from ..utils.logger import setup_logger

logger = setup_logger('websocket')

socketio = SocketIO()

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected")
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")

@socketio.on('request_update')
def handle_update_request(data):
    """Handle update request from client"""
    update_type = data.get('type')
    logger.debug(f"Update requested: {update_type}")
    # Emit requested data
    emit('update_response', {'type': update_type, 'data': {}})

def emit_alert(alert_data):
    """Emit alert to all connected clients"""
    socketio.emit('new_alert', alert_data)
    logger.debug(f"Alert emitted: {alert_data.get('signature')}")

def emit_topology_update(topology_data):
    """Emit topology update"""
    socketio.emit('topology_update', topology_data)

def emit_metrics_update(metrics_data):
    """Emit metrics update"""
    socketio.emit('metrics_update', metrics_data)
