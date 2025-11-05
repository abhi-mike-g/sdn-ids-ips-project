class TopologyVisualizer {
    constructor() {
        this.network = null;
        this.nodes = new vis.DataSet([]);
        this.edges = new vis.DataSet([]);
        this.selectedNode = null;
        this.init();
    }
    
    init() {
        this.setupNetwork();
        this.setupEventListeners();
        this.loadTopology();
    }
    
    setupNetwork() {
        const container = document.getElementById('topology-container');
        const data = {
            nodes: this.nodes,
            edges: this.edges
        };
        
        const options = {
            physics: {
                enabled: true,
                forceAtlas2Based: {
                    gravitationalConstant: -50,
                    centralGravity: 0.005,
                    springLength: 200
                },
                maxVelocity: 50,
                stabilization: { iterations: 200 }
            },
            interaction: {
                navigationButtons: true,
                keyboard: true
            },
            nodes: {
                shape: 'box',
                margin: 10,
                widthConstraint: 100,
                font: { size: 12 }
            },
            edges: {
                width: 2,
                font: { size: 10, align: 'middle' }
            }
        };
        
        this.network = new vis.Network(container, data, options);
        
        this.network.on('selectNode', (params) => {
            this.selectedNode = params.nodes[0];
            this.showNodeDetails(this.selectedNode);
        });
    }
    
    setupEventListeners() {
        document.getElementById('refresh-topology').addEventListener('click', () => {
            this.loadTopology();
        });
        
        document.getElementById('zoom-in').addEventListener('click', () => {
            this.network.getScale();
            this.network.zoomIn();
        });
        
        document.getElementById('zoom-out').addEventListener('click', () => {
            this.network.zoomOut();
        });
        
        document.getElementById('fit-view').addEventListener('click', () => {
            this.network.fit();
        });
    }
    
    loadTopology() {
        fetch('/api/topology')
            .then(r => r.json())
            .then(data => this.updateTopology(data))
            .catch(e => console.error('Failed to load topology:', e));
    }
    
    updateTopology(data) {
        // Clear existing data
        this.nodes.clear();
        this.edges.clear();
        
        // Add nodes
        data.nodes.forEach(node => {
            const nodeData = {
                id: node.id,
                label: node.label,
                title: `${node.type}: ${node.id}`,
                color: node.type === 'switch' ? '#FF9800' : '#2196F3',
                shape: node.type === 'switch' ? 'box' : 'dot',
                size: node.type === 'switch' ? 30 : 20
            };
            
            if (node.status === 'suspicious') {
                nodeData.color = '#F44336';
            }
            
            this.nodes.add(nodeData);
        });
        
        // Add edges
        data.edges.forEach(edge => {
            this.edges.add({
                from: edge.from,
                to: edge.to,
                label: edge.label,
                color: { color: '#999' },
                physics: true
            });
        });
        
        // Update statistics
        document.getElementById('topo-switches').textContent = 
            data.nodes.filter(n => n.type === 'switch').length;
        document.getElementById('topo-hosts').textContent = 
            data.nodes.filter(n => n.type === 'host').length;
        document.getElementById('topo-links').textContent = data.edges.length;
    }
    
    showNodeDetails(nodeId) {
        const node = this.nodes.get(nodeId);
        const tbody = document.getElementById('node-details-body');
        
        if (node) {
            tbody.innerHTML = `
                <tr>
                    <td>${node.id}</td>
                    <td>${node.label}</td>
                    <td><span class="badge bg-success">Active</span></td>
                    <td>${node.title}</td>
                </tr>
            `;
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new TopologyVisualizer();
});
