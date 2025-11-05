from flask import Blueprint, jsonify, request
from ..database.database import db
from ..utils.logger import setup_logger

logger = setup_logger('dashboard_api')

api_bp = Blueprint('api', __name__)

# Global references (will be set by main application)
controller_ref = None
topology_manager_ref = None

def set_references(controller, topology_manager):
    """Set references to controller and topology manager"""
    global controller_ref, topology_manager_ref
    controller_ref = controller
    topology_manager_ref = topology_manager

@api_bp.route('/status')
def get_status():
    """Get system status"""
    return jsonify({
        'status': 'running',
        'controller': 'connected' if controller_ref else 'disconnected',
        'timestamp': None  # Add actual timestamp
    })

@api_bp.route('/topology')
def get_topology():
    """Get network topology"""
    if topology_manager_ref:
        data = topology_manager_ref.get_topology_data()
        return jsonify(data)
    return jsonify({'nodes': [], 'edges': []})

@api_bp.route('/alerts')
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity', type=int)
    
    alerts = db.get_recent_alerts(limit=limit, severity=severity)
    
    return jsonify([{
        'id': alert.id,
        'timestamp': alert.timestamp.isoformat(),
        'severity': alert.severity,
        'type': alert.alert_type,
        'source_ip': alert.source_ip,
        'destination_ip': alert.destination_ip,
        'source_port': alert.source_port,
        'destination_port': alert.destination_port,
        'protocol': alert.protocol,
        'signature': alert.signature,
        'description': alert.description,
        'blocked': alert.blocked
    } for alert in alerts])

@api_bp.route('/alerts/<int:alert_id>')
def get_alert_detail(alert_id):
    """Get alert details"""
    # Implementation
    return jsonify({'id': alert_id})

@api_bp.route('/flows')
def get_flows():
    """Get active flows"""
    switch_id = request.args.get('switch_id')
    flows = db.get_active_flow_rules(switch_id=switch_id)
    
    return jsonify([{
        'id': flow.id,
        'switch_id': flow.switch_id,
        'priority': flow.priority,
        'match': flow.match_fields,
        'actions': flow.actions,
        'packet_count': flow.packet_count,
        'byte_count': flow.byte_count
    } for flow in flows])

@api_bp.route('/metrics')
def get_metrics():
    """Get system metrics"""
    import psutil
    
    return jsonify({
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'network': {
            'bytes_sent': psutil.net_io_counters().bytes_sent,
            'bytes_recv': psutil.net_io_counters().bytes_recv
        }
    })

@api_bp.route('/metrics/history')
def get_metrics_history():
    """Get metrics history"""
    hours = request.args.get('hours', 1, type=int)
    metrics = db.get_metrics_history(hours=hours)
    
    return jsonify([{
        'timestamp': m.timestamp.isoformat(),
        'cpu_usage': m.cpu_usage,
        'memory_usage': m.memory_usage,
        'active_flows': m.active_flows,
        'threats_detected': m.threats_detected
    } for m in metrics])

@api_bp.route('/block_ip', methods=['POST'])
def block_ip():
    """Block IP address"""
    data = request.get_json()
    ip = data.get('ip')
    duration = data.get('duration', 300)
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    if controller_ref:
        for datapath in controller_ref.datapaths.values():
            controller_ref.policy_enforcer.block_ip(datapath, ip, duration)
        
        return jsonify({'success': True, 'ip': ip, 'duration': duration})
    
    return jsonify({'error': 'Controller not available'}), 503

@api_bp.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    """Unblock IP address"""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    if controller_ref:
        for datapath in controller_ref.datapaths.values():
            controller_ref.policy_enforcer.unblock_ip(datapath, ip)
        
        return jsonify({'success': True, 'ip': ip})
    
    return jsonify({'error': 'Controller not available'}), 503

@api_bp.route('/statistics')
def get_statistics():
    """Get overall statistics"""
    if topology_manager_ref:
        return jsonify(topology_manager_ref.get_statistics())
    return jsonify({})
