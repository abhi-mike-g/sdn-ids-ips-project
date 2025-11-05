// dashboard/static/js/topology.js
class TopologyVisualizer {
    constructor() {
        this.nodes = new vis.DataSet([]);
        this.edges = new vis.DataSet([]);
        this.network = null;
    }
    
    updateTopology(data) {
        // Update nodes (switches, hosts)
        this.nodes.update(data.nodes.map(node => ({
            id: node.id,
            label: node.label,
            shape: node.type === 'switch' ? 'box' : 'circle',
            color: this.getNodeColor(node.status)
        })));
        
        // Update links with traffic visualization
        this.edges.update(data.links.map(link => ({
            from: link.source,
            to: link.target,
            width: this.calculateWidth(link.traffic),
            color: link.suspicious ? 'red' : 'green'
        })));
    }
}
