# network/topology.py
def create_realistic_topology():
    """
    Creates topology with external attacker simulation
    
    Internet (Simulated) ─── Firewall ─── Internal Network
         │                                      │
    Attacker                               Victim Hosts
    (separate namespace)
    """
    net = Mininet(controller=RemoteController)
    
    # External attacker (isolated namespace)
    attacker = net.addHost('attacker', ip='203.0.113.50/24')
    
    # Firewall/Gateway
    gateway = net.addSwitch('s1')
    
    # Internal network
    internal_switch = net.addSwitch('s2')
    victim1 = net.addHost('h1', ip='192.168.1.10/24')
    victim2 = net.addHost('h2', ip='192.168.1.11/24')
    
    # Connect with limited routes to simulate external access
    net.addLink(attacker, gateway)
    net.addLink(gateway, internal_switch)
    net.addLink(internal_switch, victim1)
    net.addLink(internal_switch, victim2)
    
    return net
