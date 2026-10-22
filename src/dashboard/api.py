from datetime import datetime, timezone
from collections import Counter
import ipaddress
from flask import Blueprint, current_app, jsonify, request
from .clients import ServiceUnavailable

api_bp = Blueprint('api', __name__)


def database():
    return current_app.extensions['nidps_db']


def controller():
    return current_app.extensions['controller_client']


def serialize_alert(alert):
    data = {column.name: getattr(alert, column.name) for column in alert.__table__.columns}
    data['timestamp'] = alert.timestamp.isoformat() + 'Z'
    data['type'] = data.pop('alert_type')
    return data


@api_bp.get('/status')
def get_status():
    try:
        health = controller().get('/nidps/status')
        connected = True
    except ServiceUnavailable:
        health, connected = {}, False
    return jsonify(status='running', controller='connected' if connected else 'disconnected',
                   switches=health.get('switches', 0), mode=current_app.config['NIDPS_MODE'],
                   timestamp=datetime.now(timezone.utc).isoformat())


@api_bp.get('/topology')
def get_topology():
    demo = current_app.extensions.get('demo_topology')
    if demo is not None:
        return jsonify(demo)
    try:
        return jsonify(controller().get('/nidps/topology'))
    except ServiceUnavailable:
        return jsonify(nodes=[], edges=[], available=False)


@api_bp.get('/alerts')
def get_alerts():
    limit = max(1, min(request.args.get('limit', 100, type=int), 1000))
    alerts = database().get_recent_alerts(limit, request.args.get('severity', type=int))
    return jsonify([serialize_alert(a) for a in alerts])


@api_bp.get('/alerts/<int:alert_id>')
def get_alert_detail(alert_id):
    alert = database().get_alert(alert_id)
    return (jsonify(serialize_alert(alert)), 200) if alert else (jsonify(error='Not found'), 404)


@api_bp.delete('/alerts')
def clear_alerts():
    return jsonify(deleted=database().clear_alerts())


@api_bp.get('/flows')
def get_flows():
    demo = current_app.extensions.get('demo_flows')
    if demo is not None:
        return jsonify(demo)
    flows = database().get_active_flow_rules(request.args.get('switch_id'))
    return jsonify([{'id': f.id, 'switch_id': f.switch_id, 'priority': f.priority,
                     'match': f.match_fields, 'actions': f.actions,
                     'packet_count': f.packet_count, 'byte_count': f.byte_count} for f in flows])


@api_bp.get('/security-summary')
def security_summary():
    alerts = database().get_recent_alerts(limit=10000)
    incidents = current_app.extensions.get('incident_store')
    incident_rows = incidents.recent_incidents(limit=1000) if incidents else []
    families = Counter(alert.alert_type or 'Unclassified' for alert in alerts)
    ports = Counter((alert.destination_port, (alert.protocol or 'Unknown').upper())
                    for alert in alerts if alert.destination_port)
    targets = Counter(alert.destination_ip for alert in alerts if alert.destination_ip)
    severities = Counter(str(alert.severity) for alert in alerts)
    flows = current_app.extensions.get('demo_flows')
    if flows is None:
        flows = get_flow_records()
    simulated = current_app.config['NIDPS_MODE'] == 'offline replay'
    return jsonify({
        'mode': 'Simulated replay' if simulated else 'Live telemetry',
        'alerts': len(alerts), 'incidents': len(incident_rows),
        'sources': len({a.source_ip for a in alerts if a.source_ip}),
        'targets': len(targets), 'flows': len(flows),
        'simulated_responses': sum(row.get('state') in ('simulated', 'mitigated') for row in incident_rows),
        'alert_families': [{'name': key, 'count': value} for key, value in families.most_common()],
        'targeted_ports': [{'port': key[0], 'protocol': key[1], 'count': value}
                           for key, value in ports.most_common(10)],
        'top_targets': [{'ip': key, 'count': value} for key, value in targets.most_common(8)],
        'severity_counts': dict(severities),
        'measurement_note': ('Replay counts describe supplied EVE records; they are not live packet rates.'
                             if simulated else 'Latency and throughput appear only when measured by the collector.')
    })


def get_flow_records():
    flows = database().get_active_flow_rules()
    return [{'id': f.id, 'switch_id': f.switch_id, 'priority': f.priority,
             'match': f.match_fields, 'actions': f.actions,
             'packet_count': f.packet_count, 'byte_count': f.byte_count} for f in flows]


@api_bp.get('/metrics')
def get_metrics():
    collector = current_app.extensions['metrics_collector']
    return jsonify(collector.get_current_metrics() or collector.collect_metrics())


@api_bp.get('/metrics/history')
def get_metrics_history():
    hours = max(1, min(request.args.get('hours', 1, type=int), 168))
    return jsonify([{'timestamp': m.timestamp.isoformat() + 'Z', 'cpu_usage': m.cpu_usage,
                     'memory_usage': m.memory_usage, 'active_flows': m.active_flows,
                     'threats_detected': m.threats_detected, 'throughput_mbps': m.throughput_mbps,
                     'latency_ms': m.latency_ms} for m in database().get_metrics_history(hours)])


def apply_policy(action):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='JSON object required'), 400
    try:
        data['ip'] = str(ipaddress.IPv4Address(data.get('ip', '')))
        data['duration'] = int(data.get('duration', 300))
        if not 1 <= data['duration'] <= 65535:
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify(error='Valid IPv4 and duration (1–65535 seconds) required'), 400
    try:
        result, status = controller().request('POST', '/nidps/' + action, json=data)
        return jsonify(result), status
    except ServiceUnavailable:
        return jsonify(error='Controller unavailable'), 503


@api_bp.post('/block_ip')
def block_ip():
    return apply_policy('block_ip')


@api_bp.post('/unblock_ip')
def unblock_ip():
    return apply_policy('unblock_ip')


@api_bp.get('/statistics')
def get_statistics():
    stats = database().statistics()
    try:
        stats.update(controller().get('/nidps/statistics'))
        stats['controller_available'] = True
    except ServiceUnavailable:
        stats.update(switches=0, hosts=0, links=0, blocked_ips=None, controller_available=False)
    demo_flows = current_app.extensions.get('demo_flows')
    if demo_flows is not None:
        topology = current_app.extensions.get('demo_topology', {})
        stats.update(switches=sum(n.get('type') == 'switch' for n in topology.get('nodes', [])),
                     hosts=sum(n.get('type') == 'host' for n in topology.get('nodes', [])),
                     links=len(topology.get('edges', [])), blocked_ips=0,
                     controller_available=False, telemetry_mode='simulated replay')
    stats['total_flows'] = len(demo_flows) if demo_flows is not None else len(database().get_active_flow_rules())
    return jsonify(stats)


def proxy_incidents(path):
    try:
        data, status = current_app.extensions['incident_client'].request(
            request.method, '/api/' + path, params=request.args,
            **({'json': request.get_json(silent=True) or {}} if request.method == 'POST' else {}))
        return jsonify(data), status
    except ServiceUnavailable:
        return jsonify(error='Orchestrator unavailable'), 503
