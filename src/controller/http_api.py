"""Loopback control API, served by the controller's cooperative WSGI server."""
import ipaddress
from datetime import datetime, timezone
from flask import Flask, jsonify, request
from ..utils.config import config


def create_controller_api(controller):
    app = Flask(__name__)

    @app.get('/nidps/status')
    def status():
        return jsonify(status='running', switches=len(controller.datapaths),
                       timestamp=datetime.now(timezone.utc).isoformat())

    @app.get('/nidps/topology')
    def topology():
        return jsonify(controller.topology_manager.get_topology_data())

    @app.get('/nidps/statistics')
    def statistics():
        data = controller.topology_manager.get_statistics()
        data['blocked_ips'] = len(controller.policy_enforcer.blocked_ips)
        data['controller_packets'] = controller.packet_count
        return jsonify(data)

    @app.post('/nidps/<action>')
    def policy(action):
        if action not in ('block_ip', 'unblock_ip', 'rate_limit'):
            return jsonify(error='Unknown action'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='JSON object required'), 400
        try:
            ip = str(ipaddress.IPv4Address(data.get('ip', '')))
            duration = int(data.get('duration', 300))
            rate = int(data.get('rate_kbps', 1000))
            if not 1 <= duration <= 65535 or not 1 <= rate <= 10000000:
                raise ValueError('invalid duration or rate')
        except (ValueError, TypeError):
            return jsonify(error='Valid IPv4 address, duration (1–65535), and positive rate required'), 400
        if action != 'unblock_ip' and ip in config.get('policies.protected_ips', []):
            return jsonify(error='Protected infrastructure IP'), 403
        datapaths = list(controller.datapaths.values())
        if not datapaths:
            return jsonify(error='No switches connected'), 503
        try:
            for datapath in datapaths:
                enforcer = controller.policy_enforcer
                if action == 'block_ip':
                    enforcer.block_ip(datapath, ip, duration)
                elif action == 'unblock_ip':
                    enforcer.unblock_ip(datapath, ip)
                else:
                    enforcer.rate_limit_ip(datapath, ip, rate, duration)
        except Exception as exc:
            app.logger.exception('Mitigation submission failed')
            return jsonify(error=str(exc)), 502
        # OpenFlow send_msg queues messages. Do not call this dataplane confirmation.
        return jsonify(success=True, ip=ip, switches=len(datapaths),
                       confirmation='controller-submitted', duration=duration)

    return app
