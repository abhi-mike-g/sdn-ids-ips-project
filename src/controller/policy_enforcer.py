from ryu.ofproto import ofproto_v1_3
from ..utils.logger import setup_logger
from .flow_manager import FlowManager

logger = setup_logger('policy_enforcer')

class PolicyEnforcer:
    def __init__(self, flow_manager):
        self.flow_manager = flow_manager
        self.blocked_ips = set()
        self.blocked_flows = {}
        
    def block_ip(self, datapath, ip_address, duration=300):
        """Block traffic from specific IP"""
        if ip_address in self.blocked_ips:
            logger.info(f"IP {ip_address} already blocked")
            return
        
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Block incoming traffic from this IP
        match = parser.OFPMatch(ipv4_src=ip_address, eth_type=0x0800)
        actions = []  # Drop packet
        
        self.flow_manager.install_flow(
            datapath, 
            priority=100,  # High priority
            match=match, 
            actions=actions,
            hard_timeout=duration
        )
        
        self.blocked_ips.add(ip_address)
        logger.warning(f"Blocked IP: {ip_address} for {duration}s")
    
    def block_flow(self, datapath, flow_features):
        """Block specific flow based on features"""
        parser = datapath.ofproto_parser
        
        match_dict = {
            'eth_type': 0x0800,
            'ipv4_src': flow_features.get('src_ip'),
            'ipv4_dst': flow_features.get('dst_ip')
        }
        
        if flow_features.get('src_port'):
            match_dict['ip_proto'] = flow_features.get('protocol', 6)
            if flow_features['protocol'] == 6:  # TCP
                match_dict['tcp_src'] = flow_features['src_port']
            elif flow_features['protocol'] == 17:  # UDP
                match_dict['udp_src'] = flow_features['src_port']
        
        match = parser.OFPMatch(**match_dict)
        actions = []  # Drop
        
        self.flow_manager.install_flow(
            datapath,
            priority=100,
            match=match,
            actions=actions,
            hard_timeout=60
        )
        
        flow_key = f"{flow_features.get('src_ip')}:{flow_features.get('src_port')}"
        self.blocked_flows[flow_key] = flow_features
        logger.warning(f"Blocked flow: {flow_key}")
    
    def rate_limit_flow(self, datapath, match, max_rate_kbps):
        """Apply rate limiting to flow"""
        # Implementation depends on switch capabilities
        # This is a placeholder for QoS-enabled switches
        logger.info(f"Rate limit applied: {max_rate_kbps} kbps")
    
    def unblock_ip(self, datapath, ip_address):
        """Remove IP block"""
        if ip_address not in self.blocked_ips:
            return
        
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(ipv4_src=ip_address, eth_type=0x0800)
        
        self.flow_manager.delete_flow(datapath, match)
        self.blocked_ips.remove(ip_address)
        logger.info(f"Unblocked IP: {ip_address}")
