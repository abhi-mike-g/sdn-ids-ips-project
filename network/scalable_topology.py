# network/scalable_topology.py
class ScalableTopology:
    """
    Demonstrates scalability through multiple approaches
    """
    
    def create_fat_tree_topology(self, k=4):
        """
        Fat-tree topology for demonstrating scalability
        k=4: 16 hosts, 20 switches
        k=8: 128 hosts, 80 switches
        """
        net = Mininet(controller=RemoteController)
        
        # Core layer
        core_switches = []
        for i in range((k//2)**2):
            core_switches.append(net.addSwitch(f'core_{i}'))
        
        # Aggregation layer
        agg_switches = []
        for pod in range(k):
            for i in range(k//2):
                agg_switches.append(net.addSwitch(f'agg_{pod}_{i}'))
        
        # Edge layer with hosts
        for pod in range(k):
            for i in range(k//2):
                edge = net.addSwitch(f'edge_{pod}_{i}')
                # Connect k//2 hosts to each edge switch
                for j in range(k//2):
                    host = net.addHost(f'h_{pod}_{i}_{j}')
                    net.addLink(edge, host)
        
        return net
    
    def demonstrate_horizontal_scaling(self):
        """
        Add new network segments dynamically
        """
        # Start with small topology
        initial_topology = self.create_topology(hosts=10)
        
        # Add new segment
        new_segment = self.add_network_segment(hosts=20)
        
        # Controller automatically discovers and manages new segment
        controller.discover_topology()
        
    def demonstrate_performance_under_load(self):
        """
        Measure system performance with increasing load
        """
        results = []
        for host_count in [10, 50, 100, 200]:
            topology = self.create_topology(hosts=host_count)
            metrics = self.run_load_test(topology)
            results.append({
                'hosts': host_count,
                'detection_latency': metrics.latency,
                'throughput': metrics.throughput,
                'cpu_usage': metrics.cpu
            })
        return results
