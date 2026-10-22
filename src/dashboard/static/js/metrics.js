class MetricsManager {
    constructor() {
        this.charts = {};
        this.networkSamples = [];
        this.init();
    }

    init() {
        this.initCharts();
        this.loadSecuritySummary();
        this.loadInitialData();
        socket.on('metrics_update', data => this.updateMetrics(data));
        setInterval(() => this.loadSecuritySummary(), 15000);
        setInterval(() => fetch('/api/metrics').then(r => r.json()).then(data => this.updateMetrics(data)).catch(() => {}), 5000);
    }

    initCharts() {
        const common = {responsive: true, maintainAspectRatio: true,
            scales: {x: {ticks: {color: getComputedStyle(document.documentElement).getPropertyValue('--text')}, grid: {color: getComputedStyle(document.documentElement).getPropertyValue('--border')}},
                y: {beginAtZero: true, ticks: {color: getComputedStyle(document.documentElement).getPropertyValue('--text')}, grid: {color: getComputedStyle(document.documentElement).getPropertyValue('--border')}}}};
        for (const [id, key, label, color] of [
            ['cpuHistoryChart', 'cpuHistory', 'CPU usage (%)', '#3976d2'],
            ['memoryHistoryChart', 'memoryHistory', 'Memory usage (%)', '#b86b12']]) {
            const canvas = document.getElementById(id);
            if (canvas) this.charts[key] = new Chart(canvas, {type: 'line', data: {labels: [], datasets: [{label, data: [], borderColor: color, backgroundColor: color + '22', fill: true, tension: .25}]}, options: {...common, scales: {...common.scales, y: {...common.scales.y, max: 100}}}});
        }
        const net = document.getElementById('networkChart');
        if (net) this.charts.network = new Chart(net, {type: 'line', data: {labels: [], datasets: [
            {label: 'Host bytes sent (cumulative)', data: [], borderColor: '#2673c8'},
            {label: 'Host bytes received (cumulative)', data: [], borderColor: '#15845b'}]}, options: common});
        const security = document.getElementById('securityChart');
        if (security) this.charts.security = new Chart(security, {type: 'bar', data: {labels: [], datasets: [{label: 'Alert records', data: [], backgroundColor: '#416fbe'}]}, options: {...common, indexAxis: 'y'}});
        const family = document.getElementById('familyTrendChart');
        if (family) this.charts.family = new Chart(family, {type: 'doughnut', data: {labels: [], datasets: [{label: 'Alert families', data: [], backgroundColor: ['#416fbe','#159570','#c27a12','#b5423a','#7c55ad','#16849c','#68768b']}]}, options: {responsive: true}});
    }

    async loadInitialData() {
        try {
            const history = await fetch('/api/metrics/history?hours=1').then(r => r.json());
            for (const [key, column] of [['cpuHistory', 'cpu_usage'], ['memoryHistory', 'memory_usage']]) {
                const chart = this.charts[key];
                if (!chart) continue;
                chart.data.labels = history.map(item => new Date(item.timestamp).toLocaleTimeString());
                chart.data.datasets[0].data = history.map(item => item[column]); chart.update();
            }
        } catch (_) { /* History is optional; current readings still load. */ }
        try { this.updateMetrics(await fetch('/api/metrics').then(r => r.json())); } catch (_) {}
    }

    updateMetrics(data) {
        document.getElementById('cpu-value').textContent = `${Number(data.cpu_percent || 0).toFixed(1)}%`;
        document.getElementById('memory-value').textContent = `${Number(data.memory_percent || 0).toFixed(1)}%`;
        const disk = document.getElementById('disk-value'); if (disk) disk.textContent = `${Number(data.disk_percent || 0).toFixed(1)}%`;
        document.getElementById('latency-value').textContent = data.latency_ms == null ? 'Not measured' : `${Number(data.latency_ms).toFixed(1)} ms`;
        document.getElementById('throughput-value').textContent = data.throughput_mbps == null ? 'Collecting…' : `${Number(data.throughput_mbps).toFixed(3)} Mbps`;
        document.getElementById('packet-rate-value').textContent = data.packets_per_second == null ? 'Collecting…' : `${Number(data.packets_per_second).toFixed(1)} packets/s`;
        if (data.network && this.charts.network) {
            const label = new Date().toLocaleTimeString();
            const chart = this.charts.network; chart.data.labels.push(label);
            chart.data.datasets[0].data.push(data.network.bytes_sent); chart.data.datasets[1].data.push(data.network.bytes_recv);
            while (chart.data.labels.length > 20) { chart.data.labels.shift(); chart.data.datasets.forEach(set => set.data.shift()); }
            chart.update('none');
        }
    }

    async loadSecuritySummary() {
        try {
            const data = await fetch('/api/security-summary').then(r => r.json());
            document.getElementById('security-metric-mode').textContent = `${data.mode} · ${data.measurement_note}`;
            for (const [id, value] of [['summary-alerts', data.alerts], ['summary-incidents', data.incidents],
                ['summary-sources', data.sources], ['summary-targets', data.targets], ['summary-flows', data.flows],
                ['summary-responses', data.simulated_responses]]) document.getElementById(id).textContent = value;
            document.getElementById('measurement-scope').textContent = data.mode;
            document.getElementById('metrics-method-note').textContent = data.measurement_note;
            const chart = this.charts.security;
            if (chart) { chart.data.labels = data.alert_families.map(row => row.name); chart.data.datasets[0].data = data.alert_families.map(row => row.count); chart.update(); }
            const familyChart = this.charts.family;
            if (familyChart) { familyChart.data.labels = data.alert_families.map(row => row.name); familyChart.data.datasets[0].data = data.alert_families.map(row => row.count); familyChart.update(); }
            this.fillTable('targeted-ports', data.targeted_ports, row => [row.port, row.protocol, row.count], 3);
            this.fillTable('targeted-assets', data.top_targets, row => [row.ip, row.count], 2);
        } catch (_) {
            document.getElementById('security-metric-mode').textContent = 'Security summary unavailable.';
        }
    }

    fillTable(id, records, columns) {
        const tbody = document.getElementById(id); tbody.replaceChildren();
        if (!records.length) { const row = tbody.insertRow(); const cell = row.insertCell(); cell.colSpan = columns; cell.textContent = 'No records'; return; }
        for (const record of records) { const row = tbody.insertRow(); for (const value of columns(record)) row.insertCell().textContent = value; }
    }
}

document.addEventListener('DOMContentLoaded', () => new MetricsManager());
