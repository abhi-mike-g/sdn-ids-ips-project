class TopologyVisualizer {
    constructor() {
        this.svg = document.getElementById('topology-svg');
        this.scale = 1;
        this.nodes = [];
        this.init();
    }

    init() {
        document.getElementById('refresh-topology').addEventListener('click', () => this.loadTopology());
        document.getElementById('zoom-in').addEventListener('click', () => this.zoom(0.85));
        document.getElementById('zoom-out').addEventListener('click', () => this.zoom(1.18));
        document.getElementById('fit-view').addEventListener('click', () => { this.scale = 1; this.setViewBox(); });
        socket.on('topology_update', data => this.updateTopology(data));
        this.loadTopology();
        setInterval(() => this.loadTopology(), 10000);
    }

    zoom(factor) { this.scale = Math.max(0.55, Math.min(1.8, this.scale * factor)); this.setViewBox(); }
    setViewBox() {
        const width = 1100 / this.scale, height = 600 / this.scale;
        this.svg.setAttribute('viewBox', `${(1100 - width) / 2} ${(600 - height) / 2} ${width} ${height}`);
    }

    loadTopology() {
        fetch('/api/topology').then(response => response.json())
            .then(data => this.updateTopology(data))
            .catch(() => { document.getElementById('topology-note').textContent = 'Topology service unavailable.'; });
    }

    updateTopology(data) {
        if (!data || !Array.isArray(data.nodes) || data.nodes.length === 0) {
            document.getElementById('topology-note').textContent = 'No topology data is available. Start the live lab or open the offline replay demo.';
            this.svg.replaceChildren();
            return;
        }
        this.nodes = data.nodes;
        const edges = data.edges || [];
        const flows = data.flows || [];
        this.svg.replaceChildren();
        const defs = this.element('defs');
        const marker = this.element('marker', {id: 'flow-arrow', markerWidth: 8, markerHeight: 8, refX: 7, refY: 3, orient: 'auto', markerUnits: 'strokeWidth'});
        marker.append(this.element('path', {d: 'M0,0 L0,6 L8,3 z', class: 'flow-arrow-head'}));
        defs.append(marker); this.svg.append(defs);
        const coords = this.layout(data.nodes);

        for (const edge of edges) {
            const a = coords.get(edge.from), b = coords.get(edge.to);
            if (a && b) this.drawLine(a, b, 'topology-link', edge.label || 'link');
        }
        const groups = new Map();
        for (const flow of flows) {
            const key = `${flow.source_node}|${flow.destination_node}`;
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(flow);
        }
        for (const [key, items] of groups) {
            const [source, destination] = key.split('|');
            const a = coords.get(source), b = coords.get(destination);
            if (!a || !b) continue;
            const ports = [...new Set(items.map(item => `${item.protocol || 'IP'}/${item.destination_port || '?'}`))].join(', ');
            this.drawLine(a, b, 'topology-flow', `${ports} · ${items.length} flow${items.length === 1 ? '' : 's'}`);
        }
        for (const node of data.nodes) this.drawNode(node, coords.get(node.id));

        document.getElementById('topo-switches').textContent = data.nodes.filter(n => n.type === 'switch').length;
        document.getElementById('topo-hosts').textContent = data.nodes.filter(n => n.type === 'host').length;
        document.getElementById('topo-links').textContent = edges.length;
        document.getElementById('topo-flows').textContent = flows.length;
        const note = data.mode === 'simulated replay'
            ? `Simulated topology · ${flows.length} replayed flow records · dashed red lines show alert-associated traffic, not live packets.`
            : `Live controller topology · ${flows.length} flow records.`;
        document.getElementById('topology-note').textContent = note;
        this.renderFlows(flows);
    }

    layout(nodes) {
        const switches = nodes.filter(node => node.type === 'switch');
        const hosts = nodes.filter(node => node.type !== 'switch');
        const coords = new Map();
        const switchX = 530;
        switches.forEach((node, index) => coords.set(node.id, {x: switchX, y: 210 + index * 170}));
        const actors = hosts.filter(node => node.role === 'actor');
        const services = hosts.filter(node => node.role !== 'actor');
        const place = (items, x) => items.forEach((node, index) => {
            const spacing = Math.min(88, 450 / Math.max(items.length, 1));
            coords.set(node.id, {x, y: 65 + index * spacing});
        });
        place(actors, 180); place(services, 920);
        return coords;
    }

    element(name, attrs = {}) {
        const item = document.createElementNS('http://www.w3.org/2000/svg', name);
        for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, value);
        return item;
    }

    drawLine(a, b, className, label) {
        const attrs = {x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: className};
        if (className === 'topology-flow') attrs['marker-end'] = 'url(#flow-arrow)';
        const line = this.element('line', attrs);
        const title = this.element('title'); title.textContent = label; line.append(title); this.svg.append(line);
    }

    drawNode(node, point) {
        const group = this.element('g', {class: `topology-node ${node.type === 'switch' ? 'switch-node' : 'host-node'} ${node.role || ''}`, tabindex: '0'});
        group.append(this.element(node.type === 'switch' ? 'rect' : 'circle',
            node.type === 'switch' ? {x: point.x - 60, y: point.y - 23, width: 120, height: 46, rx: 9} :
                {cx: point.x, cy: point.y, r: 25}));
        const label = this.element('text', {x: point.x, y: point.y - (node.type === 'switch' ? 2 : 2), 'text-anchor': 'middle'});
        const pieces = String(node.label || node.id).split('\n');
        pieces.forEach((piece, index) => {
            const tspan = this.element('tspan', {x: point.x, dy: index === 0 ? 0 : 14});
            tspan.textContent = piece; label.append(tspan);
        });
        group.append(label);
        const title = this.element('title'); title.textContent = `${node.type}: ${node.ip || node.id}`; group.append(title);
        group.addEventListener('click', () => this.showNodeDetails(node));
        group.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') this.showNodeDetails(node); });
        this.svg.append(group);
    }

    renderFlows(flows) {
        const tbody = document.getElementById('flow-details-body');
        tbody.replaceChildren();
        if (!flows.length) {
            const row = tbody.insertRow(); const cell = row.insertCell(); cell.colSpan = 5;
            cell.textContent = 'No flow records in this view.'; return;
        }
        for (const flow of flows) {
            const row = tbody.insertRow();
            const values = [flow.source_ip, flow.destination_ip,
                `${flow.protocol || 'IP'} / ${flow.destination_port || '—'}`,
                flow.events || flow.packet_count || 1, flow.state || 'observed'];
            for (const value of values) row.insertCell().textContent = value;
        }
    }

    showNodeDetails(node) {
        const tbody = document.getElementById('node-details-body'); tbody.replaceChildren();
        const row = tbody.insertRow();
        for (const value of [node.ip || node.id, node.type, node.status || 'active', node.label || node.id])
            row.insertCell().textContent = value;
    }
}

document.addEventListener('DOMContentLoaded', () => new TopologyVisualizer());
