from ryu.ofproto import ofproto_v1_3
from ..utils.logger import setup_logger
from ..database.database import db
import json

logger = setup_logger('flow_manager')

class FlowManager:
    def __init__(self):
        self.flows = {}  # {datapath_id: {flow_id: flow_data}}
        
    def install_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """Install flow rule on switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        
        datapath.send_msg(mod)
        
        # Store in database
        flow_data = {
            'switch_id': str(datapath.id),
            'priority': priority,
            'match_fields': json.dumps(match.to_jsondict()),
            'actions': json.dumps([str(a) for a in actions]),
            'active': True
        }
        flow_id = db.insert_flow_rule(flow_data)
        
        logger.info(f"Flow installed on switch {datapath.id}: priority={priority}")
        return flow_id
    
    def delete_flow(self, datapath, match=None):
        """Delete flow rule"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match if match else parser.OFPMatch()
        )
        
        datapath.send_msg(mod)
        logger.info(f"Flow deleted on switch {datapath.id}")
    
    def get_flow_stats(self, datapath):
        """Request flow statistics"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
