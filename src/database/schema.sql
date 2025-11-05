-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity INTEGER,
    alert_type VARCHAR(50),
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    signature VARCHAR(255),
    description TEXT,
    raw_data TEXT,
    blocked BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (blocked) REFERENCES policies(id)
);

CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);

-- Flow Rules Table
CREATE TABLE IF NOT EXISTS flow_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id VARCHAR(50),
    priority INTEGER,
    match_fields TEXT,
    actions TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_flows_switch_id ON flow_rules(switch_id);
CREATE INDEX idx_flows_active ON flow_rules(active);

-- Network Flows Table
CREATE TABLE IF NOT EXISTS network_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    packet_count INTEGER,
    byte_count INTEGER,
    duration FLOAT,
    flags VARCHAR(20),
    is_malicious BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_flows_timestamp ON network_flows(timestamp);
CREATE INDEX idx_flows_ips ON network_flows(source_ip, destination_ip);

-- System Metrics Table
CREATE TABLE IF NOT EXISTS system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    cpu_usage FLOAT,
    memory_usage FLOAT,
    active_flows INTEGER,
    threats_detected INTEGER,
    throughput_mbps FLOAT,
    latency_ms FLOAT
);

CREATE INDEX idx_metrics_timestamp ON system_metrics(timestamp);

-- Blocked IPs Table
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45),
    reason VARCHAR(255),
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_blocked_ips_active ON blocked_ips(active);

-- Policy Enforcement Table
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100),
    description TEXT,
    priority INTEGER,
    enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
