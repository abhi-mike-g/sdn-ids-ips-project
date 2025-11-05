class AlertsManager {
    constructor() {
        this.currentPage = 1;
        this.pageSize = 20;
        this.alerts = [];
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadAlerts();
    }
    
    setupEventListeners() {
        document.getElementById('severity-filter').addEventListener('change', () => {
            this.currentPage = 1;
            this.loadAlerts();
        });
        
        document.getElementById('type-filter').addEventListener('change', () => {
            this.currentPage = 1;
            this.loadAlerts();
        });
        
        document.getElementById('ip-filter').addEventListener('keyup', () => {
            this.currentPage = 1;
            this.loadAlerts();
        });
        
        document.getElementById('export-logs').addEventListener('click', () => {
            this.exportLogs();
        });
        
        document.getElementById('clear-logs').addEventListener('click', () => {
            if (confirm('Are you sure you want to clear all logs?')) {
                this.clearLogs();
            }
        });
    }
    
    loadAlerts() {
        const severity = document.getElementById('severity-filter').value;
        const type = document.getElementById('type-filter').value;
        const ip = document.getElementById('ip-filter').value;
        
        let url = `/api/alerts?limit=100`;
        if (severity) url += `&severity=${severity}`;
        
        fetch(url)
            .then(r => r.json())
            .then(data => {
                this.alerts = data;
                if (type) {
                    this.alerts = this.alerts.filter(a => a.type.includes(type));
                }
                if (ip) {
                    this.alerts = this.alerts.filter(a => 
                        a.source_ip.includes(ip) || a.destination_ip.includes(ip)
                    );
                }
                this.displayAlerts();
            })
            .catch(e => console.error('Failed to load alerts:', e));
    }
    
    displayAlerts() {
        const tbody = document.getElementById('logs-body');
        const start = (this.currentPage - 1) * this.pageSize;
        const end = start + this.pageSize;
        const pageAlerts = this.alerts.slice(start, end);
        
        if (pageAlerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="10" class="text-center text-muted">No alerts</td></tr>';
            return;
        }
        
        let html = '';
        pageAlerts.forEach(alert => {
            const severityBadge = this.getSeverityBadge(alert.severity);
            const status = alert.blocked ? '<span class="badge bg-danger">Blocked</span>' : 
                          '<span class="badge bg-warning">Detected</span>';
            
            html += `
                <tr>
                    <td><small>${new Date(alert.timestamp).toLocaleString()}</small></td>
                    <td>${severityBadge}</td>
                    <td><code>${alert.type}</code></td>
                    <td><code>${alert.source_ip}</code></td>
                    <td><code>${alert.destination_ip}</code></td>
                    <td>${alert.source_port || '-'}:${alert.destination_port || '-'}</td>
                    <td>${alert.protocol}</td>
                    <td><small>${alert.signature}</small></td>
                    <td>${status}</td>
                    <td>
                        <button class="btn btn-xs btn-danger" onclick="alertsManager.blockIP('${alert.source_ip}')">
                            Block
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tbody.innerHTML = html;
        this.updatePagination();
    }
    
    getSeverityBadge(severity) {
        const levels = {
            1: '<span class="badge bg-danger">Critical</span>',
            2: '<span class="badge bg-warning">High</span>',
            3: '<span class="badge bg-info">Medium</span>',
            4: '<span class="badge bg-secondary">Low</span>'
        };
        return levels[severity] || '<span class="badge bg-secondary">Unknown</span>';
    }
    
    updatePagination() {
        const totalPages = Math.ceil(this.alerts.length / this.pageSize);
        const pagination = document.getElementById('logs-pagination');
        
        let html = `
            <li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="alertsManager.previousPage()">Previous</a>
            </li>
        `;
        
        for (let i = 1; i <= totalPages && i <= 5; i++) {
            html += `
                <li class="page-item ${i === this.currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="alertsManager.goToPage(${i})">${i}</a>
                </li>
            `;
        }
        
        html += `
            <li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="alertsManager.nextPage()">Next</a>
            </li>
        `;
        
        pagination.innerHTML = html;
    }
    
    goToPage(page) {
        this.currentPage = page;
        this.displayAlerts();
    }
    
    previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.displayAlerts();
        }
    }
    
    nextPage() {
        const totalPages = Math.ceil(this.alerts.length / this.pageSize);
        if (this.currentPage < totalPages) {
            this.currentPage++;
            this.displayAlerts();
        }
    }
    
    blockIP(ip) {
        if (confirm(`Block IP ${ip}?`)) {
            fetch('/api/block_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, duration: 3600 })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert(`IP ${ip} has been blocked for 1 hour`);
                }
            })
            .catch(e => console.error('Failed to block IP:', e));
        }
    }
    
    exportLogs() {
        const csv = this.convertToCSV(this.alerts);
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `alerts_${new Date().toISOString()}.csv`;
        a.click();
    }
    
    convertToCSV(data) {
        const headers = ['Timestamp', 'Severity', 'Type', 'Source IP', 'Dest IP', 
                        'Port', 'Protocol', 'Signature', 'Blocked'];
        const rows = data.map(alert => [
            alert.timestamp,
            alert.severity,
            alert.type,
            alert.source_ip,
            alert.destination_ip,
            `${alert.source_port}:${alert.destination_port}`,
            alert.protocol,
            alert.signature,
            alert.blocked ? 'Yes' : 'No'
        ]);
        
        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }
    
    clearLogs() {
        // Implementation would call backend API
        console.log('Clearing logs...');
    }
}

const alertsManager = new AlertsManager();

document.addEventListener('DOMContentLoaded', () => {
    alertsManager.init();
});
