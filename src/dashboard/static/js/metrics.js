class MetricsManager {
    constructor() {
        this.socket = io();
        this.charts = {};
        this.metrics = {};
        this.historyData = [];
        this.init();
    }
    
    init() {
        this.setupSocketListeners();
        this.initCharts();
        this.loadInitialData();
        this.setupAutoRefresh();
    }
    
    setupSocketListeners() {
        this.socket.on('metrics_update', (data) => {
            this.handleMetricsUpdate(data);
        });
    }
    
    initCharts() {
        // CPU History Chart
        const cpuCtx = document.getElementById('cpuHistoryChart');
        if (cpuCtx) {
            this.charts.cpuHistory = new Chart(cpuCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'CPU Usage (%)',
                        data: [],
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    },
                    plugins: {
                        legend: { display: true }
                    }
                }
            });
        }
        
        // Memory History Chart
        const memCtx = document.getElementById('memoryHistoryChart');
        if (memCtx) {
            this.charts.memoryHistory = new Chart(memCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Memory Usage (%)',
                        data: [],
                        borderColor: 'rgb(255, 159, 64)',
                        backgroundColor: 'rgba(255, 159, 64, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    }
                }
            });
        }
        
        // Network Traffic Chart
        const netCtx = document.getElementById('networkChart');
        if (netCtx) {
            this.charts.network = new Chart(netCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Bytes Sent',
                            data: [],
                            backgroundColor: 'rgba(75, 192, 192, 0.8)'
                        },
                        {
                            label: 'Bytes Received',
                            data: [],
                            backgroundColor: 'rgba(255, 99, 132, 0.8)'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
        
        // Detection Latency Chart
        const latCtx = document.getElementById('latencyChart');
        if (latCtx) {
            this.charts.latency = new Chart(latCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Detection Latency (ms)',
                        data: [],
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
    }
    
    loadInitialData() {
        fetch('/api/metrics')
            .then(r => r.json())
            .then(data => this.handleMetricsUpdate(data))
            .catch(e => console.error('Failed to load metrics:', e));
        
        fetch('/api/metrics/history?hours=1')
            .then(r => r.json())
            .then(data => this.loadHistoryData(data))
            .catch(e => console.error('Failed to load history:', e));
    }
    
    handleMetricsUpdate(data) {
        this.metrics = data;
        this.updateDisplay();
        this.updateCharts();
    }
    
    updateDisplay() {
        // Update CPU
        document.getElementById('cpu-value').textContent = 
            this.metrics.cpu_percent?.toFixed(1) + '%' || '0%';
        
        // Update Memory
        document.getElementById('memory-value').textContent = 
            this.metrics.memory_percent?.toFixed(1) + '%' || '0%';
        
        // Update Latency
        document.getElementById('latency-value').textContent = 
            (this.metrics.latency_ms || 0).toFixed(0) + ' ms';
        
        // Update Throughput
        document.getElementById('throughput-value').textContent = 
            (this.metrics.throughput_mbps || 0).toFixed(2) + ' Mbps';
    }
    
    updateCharts() {
        const now = new Date().toLocaleTimeString();
        
        // Update CPU history
        if (this.charts.cpuHistory) {
            this.charts.cpuHistory.data.labels.push(now);
            this.charts.cpuHistory.data.datasets[0].data.push(
                this.metrics.cpu_percent || 0
            );
            
            if (this.charts.cpuHistory.data.labels.length > 30) {
                this.charts.cpuHistory.data.labels.shift();
                this.charts.cpuHistory.data.datasets[0].data.shift();
            }
            
            this.charts.cpuHistory.update('none');
        }
        
        // Update Memory history
        if (this.charts.memoryHistory) {
            this.charts.memoryHistory.data.labels.push(now);
            this.charts.memoryHistory.data.datasets[0].data.push(
                this.metrics.memory_percent || 0
            );
            
            if (this.charts.memoryHistory.data.labels.length > 30) {
                this.charts.memoryHistory.data.labels.shift();
                this.charts.memoryHistory.data.datasets[0].data.shift();
            }
            
            this.charts.memoryHistory.update('none');
        }
        
        // Update Latency
        if (this.charts.latency) {
            this.charts.latency.data.labels.push(now);
            this.charts.latency.data.datasets[0].data.push(
                this.metrics.latency_ms || 0
            );
            
            if (this.charts.latency.data.labels.length > 30) {
                this.charts.latency.data.labels.shift();
                this.charts.latency.data.datasets[0].data.shift();
            }
            
            this.charts.latency.update('none');
        }
    }
    
    loadHistoryData(data) {
        this.historyData = data;
        // Can be used for historical analysis
    }
    
    setupAutoRefresh() {
        setInterval(() => {
            fetch('/api/metrics')
                .then(r => r.json())
                .then(data => this.handleMetricsUpdate(data))
                .catch(e => console.error('Metrics update failed:', e));
        }, 5000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new MetricsManager();
});
