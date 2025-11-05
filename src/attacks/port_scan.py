import nmap
import socket
from .attack_base import AttackBase
from ..utils.logger import setup_logger

logger = setup_logger('port_scan')

class PortScanAttack(AttackBase):
    """Port scanning attack"""
    
    def __init__(self):
        super().__init__(
            name="Port Scan",
            description="Network port scanning attack"
        )
        self.nm = nmap.PortScanner()
    
    def execute(self, target, ports='1-1024', scan_type='syn', delay=0):
        """Execute port scan"""
        logger.info(f"Starting port scan: {target} ports {ports}")
        
        try:
            # Use nmap for comprehensive scanning
            if scan_type == 'syn':
                self.nm.scan(target, ports, arguments='-sS')
            elif scan_type == 'connect':
                self.nm.scan(target, ports, arguments='-sT')
            elif scan_type == 'stealth':
                self.nm.scan(target, ports, arguments='-sS -T2')
            else:
                self.nm.scan(target, ports)
            
            results = self._parse_results(target)
            
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            # Fallback to simple socket scan
            results = self._simple_port_scan(target, ports, delay)
        
        logger.info(f"Port scan completed: {len(results.get('open_ports', []))} open ports")
        return results
    
    def _parse_results(self, target):
        """Parse nmap results"""
        results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }
        
        try:
            for proto in self.nm[target].all_protocols():
                ports = self.nm[target][proto].keys()
                for port in ports:
                    state = self.nm[target][proto][port]['state']
                    service = self.nm[target][proto][port].get('name', 'unknown')
                    
                    port_info = {
                        'port': port,
                        'protocol': proto,
                        'state': state,
                        'service': service
                    }
                    
                    if state == 'open':
                        results['open_ports'].append(port_info)
                    elif state == 'closed':
                        results['closed_ports'].append(port_info)
                    else:
                        results['filtered_ports'].append(port_info)
        except Exception as e:
            logger.error(f"Parse error: {e}")
        
        return results
    
    def _simple_port_scan(self, target, ports, delay):
        """Simple socket-based port scan"""
        import time
        
        results = {'open_ports': [], 'closed_ports': []}
        
        # Parse port range
        if '-' in str(ports):
            start, end = map(int, ports.split('-'))
            port_list = range(start, end + 1)
        else:
            port_list = [int(ports)]
        
        for port in port_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    results['open_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open'
                    })
                    logger.debug(f"Port {port} is open")
                else:
                    results['closed_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'closed'
                    })
            except Exception as e:
                logger.debug(f"Port {port} error: {e}")
            finally:
                sock.close()
            
            if delay > 0:
                time.sleep(delay)
        
        return results
