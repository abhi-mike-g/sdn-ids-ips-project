// Dashboard main functionality
class Dashboard {
    constructor() {
        this.socket = io();
        this.charts = {};
        this.alerts = [];
        this.init();
    }
    
    init() {
        this.setupSocketListeners();
        this.loadInitialData();
        this.initCharts();
        this.setupAutoRefresh();
    }
    
    setupSocketListeners() {
        this.socket.on('new_alert', (data) => {
            this.handleNewAlert(data);
        });
        
        this.socket.on('metrics_update', (data) => {
            this.updateMetrics(data);
        });
        
        this.socket.on('topology_update', (data) => {
            this.updateTopology(data);
        });
    }
    
    loadInitialData() {
        // Load initial alerts
        fetch('/api/alerts?limit=20')
            .then(r => r.json())
            .then(data => {
                this.alerts = data;
                this.updateAlertsDisplay();
            })
            .catch(e => console.error('Failed to load alerts:', e));
        
        // Load initial metrics
        fetch('/api/metrics')
            .then(r => r.json())
            .then(data => this.updateMetrics(data))
            .catch(e => console.error('Failed to load metrics:', e));
        
        // Load topology statistics
        fetch('/api/statistics')
            .then(r => r.json())
            .then(data => this.updateStatistics(data))
            .catch(e => console.error('Failed to load statistics:', e));
    }
    
    initCharts() {
        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart');
        if (trafficCtx) {
            this.charts.traffic = new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Packets/sec',
                            data: [],
                            borderColor: 'rgb(75, 192, 192)',
                            backgroundColor: 'rgba(75, 192, 192, 0.1)',
                            tension: 0.1
                        },
                        {
                            label: 'Threats',
                            data: [],
                            borderColor: 'rgb(255, 99, 132)',
                            backgroundColor: 'rgba(255, 99, 132, 0.1)',
                            tension: 0.1,
                            yAxisID: 'y1'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    interaction: { mode: 'index', intersect: false },
                    scales: {
                        y: { beginAtZero: true },
                        y1: {
                            type: 'linear',
                            display: true,
                            position: 'right',
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        // Threat Timeline
        const timelineCtx = document.getElementById('threatTimeline');
        if (timelineCtx) {
            this.charts.timeline = new Chart(timelineCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Threats Detected',
                        data: [],
                        backgroundColor: 'rgba(255, 99, 132, 0.8)',
                        borderColor: 'rgb(255, 99, 132)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: { y: { beginAtZero: true } }
                }
            });
        }
        
        // Attack Types Distribution
        const attackCtx = document.getElementById('attackTypesChart');
        if (attackCtx) {
            this.charts.attacks = new Chart(attackCtx, {
                type: 'doughnut',
                data: {
                    labels: ['DoS', 'Port Scan', 'SQL Injection', 'Brute Force', 'MITM'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            'rgb(255, 99, 132)',
                            'rgb(54, 162, 235)',
                            'rgb(255, 206, 86)',
                            'rgb(75, 192, 192)',
                            'rgb(153, 102, 255)'
                        ]
                    }]
                },
                options: { responsive: true }
            });
        }
    }
    
    handleNewAlert(alert) {
        this.alerts.unshift(alert);
        if (this.alerts.length > 100) {
            this.alerts.pop();
        }
        this.updateAlertsDisplay();
        
        // Update statistics
        document.getElementById('active-threats').textContent = 
            parseInt(document.getElementById('active-threats').textContent) + 1;
    }
    
    updateAlertsDisplay() {
        const alertsList = document.getElementById('alerts-list');
        if (!alertsList) return;
        
        if (this.alerts.length === 0) {
            alertsList.innerHTML = '<p class="text-muted">No recent alerts</p>';
            return;
        }
        
        let html = '';
        this.alerts.slice(0, 10).forEach(alert => {
            const severityClass = this.getSeverityClass(alert.severity);
            const severityText = this.getSeverityText(alert.severity);
            
            html += `
                <div class="alert alert-${severityClass} alert-dismissible fade show mb-2" role="alert">
                    <strong>${severityText}:</strong> ${alert.signature}
                    <br/>
                    <small class="text-muted">
                        ${alert.source_ip}:${alert.source_port} → ${alert.destination_ip}:${alert.destination_port}
                        <br/>
                        ${new Date(alert.timestamp).toLocaleTimeString()}
                    </small>
                </div>
            `;
        });
        
        alertsList.innerHTML = html;
    }
    
    updateMetrics(metrics) {
        // Update CPU
        document.getElementById('cpu-progress').style.width = metrics.cpu_percent + '%';
        document.getElementById('cpu-progress').textContent = metrics.cpu_percent.toFixed(1) + '%';
        
        // Update Memory
        document.getElementById('memory-progress').style.width = metrics.memory_percent + '%';
        document.getElementById('memory-progress').textContent = metrics.memory_percent.toFixed(1) + '%';
        
        // Update chart data
        if (this.charts.traffic) {
            const now = new Date().toLocaleTimeString();
            this.charts.traffic.data.labels.push(now);
            this.charts.traffic.data.datasets[0].data.push(metrics.cpu_percent);
            
            if (this.charts.traffic.data.labels.length > 20) {
                this.charts.traffic.data.labels.shift();
                this.charts.traffic.data.datasets.forEach(ds => ds.data.shift());
            }
            
            this.charts.traffic.update();
        }
    }
    
    updateStatistics(stats) {
        document.getElementById('switch-count').textContent = stats.switches || 0;
        document.getElementById('active-flows').textContent = stats.total_flows || 0;
    }
    
    updateTopology(topology) {
        // Update topology statistics
        document.getElementById('topo-switches').textContent = 
            topology.nodes.filter(n => n.type === 'switch').length;
        document.getElementById('topo-hosts').textContent = 
            topology.nodes.filter(n => n.type === 'host').length;
        document.getElementById('topo-links').textContent = topology.edges.length;
    }
    
    getSeverityClass(severity) {
        if (severity <= 1) return 'danger';
        if (severity <= 2) return 'warning';
        if (severity <= 3) return 'info';
        return 'light';
    }
    
    getSeverityText(severity) {
        if (severity <= 1) return 'CRITICAL';
        if (severity <= 2) return 'HIGH';
        if (severity <= 3) return 'MEDIUM';
        return 'LOW';
    }
    
    setupAutoRefresh() {
        setInterval(() => {
            fetch('/api/metrics')
                .then(r => r.json())
                .then(data => this.updateMetrics(data))
                .catch(e => console.error('Metrics update failed:', e));
        }, 5000);
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    new Dashboard();
});
