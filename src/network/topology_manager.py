from collections import defaultdict
from ..utils.logger import setup_logger

logger = setup_logger('topology_manager')

class TopologyManager:
    def __init__(self):
        self.switches = {}  # {dpid: switch_info}
        self.hosts = {}  # {mac: host_info}
        self.links = []  # [(switch1, port1, switch2, port2)]
        self.mac_to_port = defaultdict(dict)  # {dpid: {mac: port}}
        
    def add_switch(self, dpid):
        """Add switch to topology"""
        if dpid not in self.switches:
            self.switches[dpid] = {
                'dpid': dpid,
                'ports': {},
                'flows': 0,
                'status': 'active'
            }
            logger.info(f"Switch added: {dpid}")
    
    def remove_switch(self, dpid):
        """Remove switch from topology"""
        if dpid in self.switches:
            del self.switches[dpid]
            logger.info(f"Switch removed: {dpid}")
    
    def add_host(self, mac, ip=None, switch_dpid=None, port=None):
        """Add host to topology"""
        if mac not in self.hosts:
            self.hosts[mac] = {
                'mac': mac,
                'ip': ip,
                'switch': switch_dpid,
                'port': port,
                'first_seen': None,
                'last_seen': None
            }
            logger.info(f"Host added: {mac} ({ip})")
    
    def add_link(self, src_dpid, src_port, dst_dpid, dst_port):
        """Add link between switches"""
        link = (src_dpid, src_port, dst_dpid, dst_port)
        if link not in self.links:
            self.links.append(link)
            logger.info(f"Link added: {src_dpid}:{src_port} <-> {dst_dpid}:{dst_port}")
    
    def update_mac_port(self, dpid, mac, port):
        """Update MAC to port mapping"""
        self.mac_to_port[dpid][mac] = port
    
    def get_topology_data(self):
        """Get topology data for visualization"""
        nodes = []
        edges = []
        
        # Add switches as nodes
        for dpid, switch_info in self.switches.items():
            nodes.append({
                'id': f's{dpid}',
                'label': f'S{dpid}',
                'type': 'switch',
                'status': switch_info['status'],
                'group': 'switch'
            })
        
        # Add hosts as nodes
        for mac, host_info in self.hosts.items():
            nodes.append({
                'id': mac,
                'label': host_info.get('ip', mac),
                'type': 'host',
                'group': 'host'
            })
        
        # Add links as edges
        for src_dpid, src_port, dst_dpid, dst_port in self.links:
            edges.append({
                'from': f's{src_dpid}',
                'to': f's{dst_dpid}',
                'label': f'{src_port}-{dst_port}'
            })
        
        # Add host connections
        for mac, host_info in self.hosts.items():
            if host_info['switch']:
                edges.append({
                    'from': mac,
                    'to': f's{host_info["switch"]}',
                    'label': f'p{host_info["port"]}'
                })
        
        return {'nodes': nodes, 'edges': edges}
    
    def get_statistics(self):
        """Get topology statistics"""
        return {
            'switches': len(self.switches),
            'hosts': len(self.hosts),
            'links': len(self.links),
            'total_flows': sum(s.get('flows', 0) for s in self.switches.values())
        }
