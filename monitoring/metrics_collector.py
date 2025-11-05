# monitoring/metrics_collector.py
class ScalabilityMetrics:
    def collect_metrics(self):
        return {
            'network_size': {
                'switches': len(self.topology.switches),
                'hosts': len(self.topology.hosts),
                'links': len(self.topology.links)
            },
            'performance': {
                'flows_per_second': self.measure_flow_rate(),
                'detection_latency_ms': self.measure_detection_latency(),
                'rule_installation_time_ms': self.measure_rule_installation()
            },
            'resource_utilization': {
                'controller_cpu_percent': psutil.cpu_percent(),
                'controller_memory_mb': psutil.virtual_memory().used / 1024 / 1024,
                'switch_table_occupancy': self.measure_table_occupancy()
            },
            'scalability_index': self.calculate_scalability_score()
        }
