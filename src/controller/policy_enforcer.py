"""Per-switch mitigation state with bounded OpenFlow lifetimes."""
import ipaddress
import time
import zlib


class PolicyEnforcer:
    def __init__(self, flow_manager, clock=None):
        self.flow_manager = flow_manager
        self.clock = clock or time.monotonic
        self.blocks = {}
        self.meters = {}
        self.blocked_flows = {}

    @property
    def blocked_ips(self):
        now = self.clock()
        self.blocks = {key: expiry for key, expiry in self.blocks.items() if expiry > now}
        return {ip for _, ip in self.blocks}

    def block_ip(self, datapath, ip_address, duration=300):
        ip_address = str(ipaddress.IPv4Address(ip_address))
        if not 1 <= duration <= 65535:
            raise ValueError('duration must be between 1 and 65535 seconds')
        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        self.flow_manager.install_flow(datapath, 40000, match, [], hard_timeout=duration)
        self.blocks[(datapath.id, ip_address)] = self.clock() + duration
        return True

    def block_flow(self, datapath, flow_features):
        # Cover changing source ports too. The caller checks the allowlist.
        return self.block_ip(datapath, flow_features['src_ip'], duration=60)

    def rate_limit_ip(self, datapath, ip_address, max_rate_kbps=1000, duration=300):
        ip_address = str(ipaddress.IPv4Address(ip_address))
        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        return self.rate_limit_flow(datapath, match, max_rate_kbps, duration, ip_address)

    def rate_limit_flow(self, datapath, match, max_rate_kbps, duration=300, ip_address=None):
        if not 1 <= int(max_rate_kbps) <= 10000000 or not 1 <= int(duration) <= 65535:
            raise ValueError('invalid rate or duration')
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        ip_address = ip_address or str(match)
        key = (datapath.id, ip_address)
        meter_id = zlib.crc32(ip_address.encode()) % 0xffff0000 + 1
        command = ofproto.OFPMC_MODIFY if key in self.meters else ofproto.OFPMC_ADD
        datapath.send_msg(parser.OFPMeterMod(
            datapath=datapath, command=command, flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id, bands=[parser.OFPMeterBandDrop(rate=int(max_rate_kbps), burst_size=0)]))
        self.meters[key] = meter_id
        instructions = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                         [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])]
        self.flow_manager.install_flow(datapath, 30000, match, [], hard_timeout=duration,
                                       instructions=instructions)
        return True

    def unblock_ip(self, datapath, ip_address):
        ip_address = str(ipaddress.IPv4Address(ip_address))
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_address)
        self.flow_manager.delete_flow(datapath, match)
        key = (datapath.id, ip_address)
        self.blocks.pop(key, None)
        meter_id = self.meters.pop(key, None)
        if meter_id is not None:
            datapath.send_msg(parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_DELETE,
                                               flags=0, meter_id=meter_id))
        return True
