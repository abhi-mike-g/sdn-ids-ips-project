from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from .flow_manager import FlowManager
from .policy_enforcer import PolicyEnforcer
from .threat_detector import ThreatDetector
from ..detection.suricata_monitor import SuricataMonitor
from ..network.topology_manager import TopologyManager
from ..database.database import db
from ..utils.logger import setup_logger
from ..utils.config import config

logger = setup_logger('sdn_controller')

class SDNIDPSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SDNIDPSController, self).__init__(*args, **kwargs)
        
        # Initialize components
        self.flow_manager = FlowManager()
        self.policy_enforcer = PolicyEnforcer(self.flow_manager)
        self.threat_detector = ThreatDetector()
        self.topology_manager = TopologyManager()
        
        # Data structures
        self.datapaths = {}
        self.mac_to_port = {}
        
        # Start Suricata monitor
        self.suricata = SuricataMonitor(self.handle_suricata_alert)
        self.suricata.start()
        
        logger.info("SDN NIDPS Controller initialized")
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Handle switch connection state changes"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.topology_manager.add_switch(datapath.id)
                logger.info(f"Switch connected: {datapath.id}")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.topology_manager.remove_switch(datapath.id)
                logger.warning(f"Switch disconnected: {datapath.id}")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.flow_manager.install_flow(datapath, 0, match, actions)
        
        logger.info(f"Switch features configured: {datapath.id}")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Extract packet info
        flow_features = self.extract_flow_features(pkt, in_port, datapath.id)
        
        # Threat detection
        threat_result = self.threat_detector.analyze_packet(flow_features)
        
        if threat_result['is_threat']:
            logger.warning(f"Threat detected: {threat_result['threat_type']} from {flow_features.get('src_ip')}")
            
            # Enforce policy
            self.policy_enforcer.block_flow(datapath, flow_features)
            
            # Log to database
            db.insert_alert({
                'severity': threat_result.get('severity', 2),
                'alert_type': threat_result['threat_type'],
                'source_ip': flow_features.get('src_ip'),
                'destination_ip': flow_features.get('dst_ip'),
                'source_port': flow_features.get('src_port'),
                'destination_port': flow_features.get('dst_port'),
                'protocol': flow_features.get('protocol_name'),
                'signature': threat_result.get('signature', ''),
                'description': threat_result.get('description', ''),
                'blocked': True
            })
            
            # Don't forward malicious packet
            return
        
        # Normal L2 learning switch logic
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.flow_manager.install_flow(datapath, 1, match, actions, 
                                          idle_timeout=60, hard_timeout=300)
        
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def extract_flow_features(self, pkt, in_port, switch_id):
        """Extract features from packet for analysis"""
        features = {
            'switch_id': switch_id,
            'in_port': in_port,
            'timestamp': None  # Add actual timestamp
        }
        
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt:
            features['eth_src'] = eth_pkt.src
            features['eth_dst'] = eth_pkt.dst
            features['eth_type'] = eth_pkt.ethertype
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            features['src_ip'] = ip_pkt.src
            features['dst_ip'] = ip_pkt.dst
            features['protocol'] = ip_pkt.proto
            features['ttl'] = ip_pkt.ttl
            features['total_length'] = ip_pkt.total_length
            
            if ip_pkt.proto == 6:  # TCP
                features['protocol_name'] = 'TCP'
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    features['src_port'] = tcp_pkt.src_port
                    features['dst_port'] = tcp_pkt.dst_port
                    features['tcp_flags'] = tcp_pkt.bits
            elif ip_pkt.proto == 17:  # UDP
                features['protocol_name'] = 'UDP'
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    features['src_port'] = udp_pkt.src_port
                    features['dst_port'] = udp_pkt.dst_port
            elif ip_pkt.proto == 1:  # ICMP
                features['protocol_name'] = 'ICMP'
        
        return features
    
    def handle_suricata_alert(self, alert):
        """Process alerts from Suricata"""
        logger.warning(f"Suricata alert: {alert.get('alert', {}).get('signature')}")
        
        # Extract IPs from alert
        src_ip = alert.get('src_ip')
        severity = alert.get('alert', {}).get('severity', 3)
        
        # Block if critical/high severity
        if severity <= 2 and src_ip:
            for dpid, datapath in self.datapaths.items():
                self.policy_enforcer.block_ip(datapath, src_ip)
        
        # Store in database
        db.insert_alert({
            'severity': severity,
            'alert_type': alert.get('alert', {}).get('category', 'Unknown'),
            'source_ip': src_ip,
            'destination_ip': alert.get('dest_ip'),
            'source_port': alert.get('src_port'),
            'destination_port': alert.get('dest_port'),
            'protocol': alert.get('proto', '').upper(),
            'signature': alert.get('alert', {}).get('signature', ''),
            'description': alert.get('alert', {}).get('description', ''),
            'raw_data': str(alert),
            'blocked': severity <= 2
        })
