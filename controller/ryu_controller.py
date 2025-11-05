# controller/ryu_controller.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from detection.suricata_integration import SuricataMonitor
from controller.threat_detector import ThreatDetector
from controller.policy_enforcer import PolicyEnforcer

class SDNIDPSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SDNIDPSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.threat_detector = ThreatDetector()
        self.policy_enforcer = PolicyEnforcer()
        
        # Initialize Suricata integration
        self.suricata = SuricataMonitor()
        self.suricata.add_callback(self.handle_suricata_alert)
        self.suricata.start_monitoring()
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Extract flow features
        flow_features = self.extract_flow_features(pkt)
        
        # Real-time threat detection
        is_threat, threat_type = self.threat_detector.analyze(flow_features)
        
        if is_threat:
            self.logger.warning(f"Threat detected: {threat_type}")
            self.policy_enforcer.block_flow(datapath, flow_features)
            self.log_incident(threat_type, flow_features)
            return
        
        # Normal forwarding logic
        self.normal_forwarding(msg, pkt, eth)
    
    def handle_suricata_alert(self, alert):
        """Process Suricata IDS alerts"""
        severity = alert['alert']['severity']
        src_ip = alert['src_ip']
        dst_ip = alert['dest_ip']
        
        if severity <= 2:  # Critical/High
            self.logger.critical(f"Suricata Alert: {alert['alert']['signature']}")
            # Install blocking flow rule
            for datapath_id, datapath in self.datapaths.items():
                self.policy_enforcer.block_ip(datapath, src_ip)
        
        # Store in database
        self.db.insert_alert(alert)
        
        # Push to dashboard
        self.dashboard.emit_alert({
            'timestamp': alert['timestamp'],
            'severity': severity,
            'source': src_ip,
            'destination': dst_ip,
            'signature': alert['alert']['signature']
        })
