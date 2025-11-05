from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from ..utils.logger import setup_logger
from ..utils.config import config

logger = setup_logger('topology')

class NetworkTopology:
    def __init__(self, controller_ip='127.0.0.1', controller_port=6653):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.net = None
        
    def create_simple_topology(self):
        """Create simple topology for testing"""
        info('*** Creating Simple Topology\n')
        
        self.net = Mininet(
            controller=RemoteController,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True
        )
        
        # Add controller
        info('*** Adding controller\n')
        c0 = self.net.addController(
            'c0',
            controller=RemoteController,
            ip=self.controller_ip,
            port=self.controller_port
        )
        
        # Add switches
        info('*** Adding switches\n')
        s1 = self.net.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.net.addSwitch('s2', protocols='OpenFlow13')
        
        # Add hosts
        info('*** Adding hosts\n')
        h1 = self.net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        
        # Add links
        info('*** Adding links\n')
        self.net.addLink(s1, s2)
        self.net.addLink(h1, s1)
        self.net.addLink(h2, s1)
        self.net.addLink(h3, s2)
        self.net.addLink(h4, s2)
        
        return self.net
    
    def create_realistic_topology(self):
        """Create topology with external attacker simulation"""
        info('*** Creating Realistic Topology with External Attacker\n')
        
        self.net = Mininet(
            controller=RemoteController,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True
        )
        
        # Add controller
        c0 = self.net.addController(
            'c0',
            controller=RemoteController,
            ip=self.controller_ip,
            port=self.controller_port
        )
        
        # Gateway/Firewall switch
        gateway = self.net.addSwitch('s1', protocols='OpenFlow13')
        
        # Internal switches
        internal1 = self.net.addSwitch('s2', protocols='OpenFlow13')
        internal2 = self.net.addSwitch('s3', protocols='OpenFlow13')
        
        # External attacker (simulated external network)
        attacker = self.net.addHost(
            'attacker',
            ip='203.0.113.50/24',
            mac='00:00:00:00:00:ff'
        )
        
        # Internal victims
        victim1 = self.net.addHost('victim1', ip='192.168.1.10/24', mac='00:00:00:00:01:01')
        victim2 = self.net.addHost('victim2', ip='192.168.1.11/24', mac='00:00:00:00:01:02')
        victim3 = self.net.addHost('victim3', ip='192.168.1.12/24', mac='00:00:00:00:01:03')
        
        # Web server (vulnerable)
        webserver = self.net.addHost('webserver', ip='192.168.1.100/24', mac='00:00:00:00:01:ff')
        
        # Links
        self.net.addLink(attacker, gateway)  # External connection
        self.net.addLink(gateway, internal1)
        self.net.addLink(gateway, internal2)
        self.net.addLink(victim1, internal1)
        self.net.addLink(victim2, internal1)
        self.net.addLink(victim3, internal2)
        self.net.addLink(webserver, internal2)
        
        return self.net
    
    def create_scalable_topology(self, num_switches=4, hosts_per_switch=5):
        """Create scalable fat-tree-like topology"""
        info(f'*** Creating Scalable Topology: {num_switches} switches, {hosts_per_switch} hosts each\n')
        
        self.net = Mininet(
            controller=RemoteController,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True
        )
        
        # Add controller
        c0 = self.net.addController(
            'c0',
            controller=RemoteController,
            ip=self.controller_ip,
            port=self.controller_port
        )
        
        # Core switch
        core = self.net.addSwitch('score', protocols='OpenFlow13')
        
        switches = []
        for i in range(num_switches):
            # Add edge switch
            switch = self.net.addSwitch(f's{i+1}', protocols='OpenFlow13')
            switches.append(switch)
            
            # Connect to core
            self.net.addLink(switch, core)
            
            # Add hosts to this switch
            for j in range(hosts_per_switch):
                host_num = i * hosts_per_switch + j + 1
                host = self.net.addHost(
                    f'h{host_num}',
                    ip=f'10.0.{i}.{j+1}/24',
                    mac=f'00:00:00:00:{i:02x}:{j+1:02x}'
                )
                self.net.addLink(host, switch)
        
        return self.net
    
    def start(self):
        """Start the network"""
        if self.net:
            info('*** Starting network\n')
            self.net.start()
            info('*** Network started\n')
            return True
        return False
    
    def stop(self):
        """Stop the network"""
        if self.net:
            info('*** Stopping network\n')
            self.net.stop()
            info('*** Network stopped\n')
    
    def cli(self):
        """Start Mininet CLI"""
        if self.net:
            CLI(self.net)
    
    def pingAll(self):
        """Test connectivity"""
        if self.net:
            return self.net.pingAll()

def create_and_run_topology(topology_type='simple'):
    """Helper function to create and run topology"""
    setLogLevel('info')
    
    topo = NetworkTopology()
    
    if topology_type == 'simple':
        topo.create_simple_topology()
    elif topology_type == 'realistic':
        topo.create_realistic_topology()
    elif topology_type == 'scalable':
        topo.create_scalable_topology(num_switches=6, hosts_per_switch=8)
    
    topo.start()
    
    info('*** Running connectivity test\n')
    topo.pingAll()
    
    info('*** Starting CLI\n')
    topo.cli()
    
    topo.stop()

if __name__ == '__main__':
    import sys
    topo_type = sys.argv[1] if len(sys.argv) > 1 else 'simple'
    create_and_run_topology(topo_type)
