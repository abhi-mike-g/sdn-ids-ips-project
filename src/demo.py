"""Offline replay with the real dashboard, database and incident engine."""
import argparse
from collections import Counter
import ipaddress
import tempfile
from pathlib import Path
from orchestrator.eve_watcher import read_alerts
from orchestrator.store import Store
from orchestrator.correlation import Correlator
from orchestrator.policy import PolicyConfig
from orchestrator.ryu_client import RyuClient
from orchestrator.orchestrator import Orchestrator
from .database.database import DatabaseManager
from .dashboard.app import create_app, run_dashboard
from .utils.config import config


def build_demo(path, directory):
    store = Store(str(Path(directory) / 'incidents.db'))
    database = DatabaseManager('sqlite:///' + str(Path(directory) / 'alerts.db'))
    engine = Orchestrator(store, Correlator(), PolicyConfig(protected_ips={'10.0.0.254'}),
                          RyuClient(dry_run=True))
    count = 0
    flows = {}
    observed_hosts = set()
    for record in read_alerts(path):
        engine.handle_raw(record)
        alert = record.get('alert', {})
        database.insert_alert({'severity': alert.get('severity', 3),
                               'alert_type': alert.get('category', 'Replay'),
                               'source_ip': record.get('src_ip'),
                               'destination_ip': record.get('dest_ip'),
                               'source_port': record.get('src_port'),
                               'destination_port': record.get('dest_port'),
                               'signature': alert.get('signature'),
                               'protocol': record.get('proto'), 'blocked': False})
        source, destination = record.get('src_ip'), record.get('dest_ip')
        if source:
            observed_hosts.add(source)
        if destination:
            observed_hosts.add(destination)
        if source and destination:
            key = (source, destination, record.get('src_port'), record.get('dest_port'), record.get('proto'))
            flow = flows.setdefault(key, {'source_ip': source, 'destination_ip': destination,
                                          'source_port': record.get('src_port'),
                                          'destination_port': record.get('dest_port'),
                                          'protocol': record.get('proto'), 'events': 0,
                                          'signature': alert.get('signature', ''), 'state': 'replayed'})
            flow['events'] += 1
        count += 1
    app = create_app(database=database, incident_store=store, orchestrator=engine)
    host_labels = {
        '10.0.0.1': 'Web server', '10.0.0.2': 'DNS resolver',
        '10.0.0.3': 'Database', '10.0.0.4': 'File service',
        '10.0.0.5': 'IoT broker',
    }
    nodes = [
        {'id': 's1', 'label': 'Edge switch', 'type': 'switch', 'status': 'active'},
        {'id': 's2', 'label': 'Service switch', 'type': 'switch', 'status': 'active'},
    ]
    edges = [{'from': 's1', 'to': 's2', 'label': 'trunk · OpenFlow 1.3'}]
    for host_ip in sorted(observed_hosts, key=lambda value: int(ipaddress.ip_address(value))):
        is_actor = ipaddress.ip_address(host_ip) in ipaddress.ip_network('10.0.0.96/27')
        node_id = 'host-' + host_ip.replace('.', '-')
        nodes.append({'id': node_id,
                      'label': f"{host_labels.get(host_ip, 'Replay actor' if is_actor else 'Lab host')}\n{host_ip}",
                      'type': 'host', 'ip': host_ip,
                      'role': 'actor' if is_actor else 'service', 'status': 'simulated'})
        edges.append({'from': node_id, 'to': 's1' if is_actor else 's2',
                      'label': 'access port'})
    demo_flows = []
    for index, flow in enumerate(flows.values(), 1):
        flow['id'] = index
        flow['source_node'] = 'host-' + flow['source_ip'].replace('.', '-').replace(':', '-')
        flow['destination_node'] = 'host-' + flow['destination_ip'].replace('.', '-').replace(':', '-')
        demo_flows.append(flow)
    topology = {'nodes': nodes, 'edges': edges, 'flows': demo_flows,
                'available': True, 'mode': 'simulated replay'}
    app.extensions['demo_topology'] = topology
    app.extensions['demo_flows'] = demo_flows
    return app, store, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', default=str(config.root / 'orchestrator/demo_scenarios.jsonl'))
    parser.add_argument('--check', action='store_true', help='validate replay and HTTP routes without serving')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='nidps-demo-') as directory:
        app, store, count = build_demo(args.replay, directory)
        print(f'Offline replay: {count} alerts, {len(store.recent_incidents())} incidents; no live blocking.')
        if args.check:
            client = app.test_client()
            for path in ['/', '/topology', '/logs', '/metrics', '/incidents',
                         '/api/alerts', '/api/topology', '/api/metrics',
                         '/api/incidents', '/api/stats']:
                response = client.get(path)
                if response.status_code != 200:
                    raise RuntimeError(f'{path} failed: {response.status_code}')
            print('Replay and dashboard checks passed.')
        else:
            run_dashboard(app)


if __name__ == '__main__':
    main()
