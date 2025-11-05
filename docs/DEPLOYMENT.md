# SDN-NIDPS Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Development Setup](#development-setup)
3. [Production Setup](#production-setup)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- Ubuntu 20.04 LTS or later
- 4GB RAM minimum (8GB recommended)
- 10GB disk space
- 2+ CPU cores
- Root or sudo access

### Software Requirements
- Python 3.8+
- pip3
- Git
- Docker (for containerized deployment)

## Development Setup

### 1. Clone Repository
```bash
git clone <repository-url>
cd sdn-nidps-project
```

### 2. Run Setup Script
```bash
sudo bash setup.sh
```

### 3. Configure Environment
```bash
cp config/controller_config.json.example config/controller_config.json
# Edit configuration as needed
nano config/controller_config.json
```

### 4. Start Services
```bash
# Terminal 1: Start controller
ryu-manager src/controller/sdn_controller.py

# Terminal 2: Start dashboard
python3 src/dashboard/app.py

# Terminal 3: Create topology
sudo python3 src/network/topology.py simple
```

### 5. Access Dashboard
Open browser: `http://localhost:5000`

## Production Setup

### 1. Security Hardening

#### Enable TLS
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# Update configuration
nano config/controller_config.json
# Set: "enable_tls": true, "certificate_path": "cert.pem", "key_path": "key.pem"
```

#### Implement Authentication
```python
# In src/dashboard/app.py
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Implement secure verification
    pass

@app.route('/api/alerts')
@auth.login_required
def get_alerts():
    # Protected endpoint
    pass
```

### 2. Database Configuration

#### Use PostgreSQL
```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database
sudo -u postgres createdb nidps_db

# Update configuration
nano config/controller_config.json
# Set: "database.url": "postgresql://user:password@localhost/nidps_db"
```

#### Enable Database Backups
```bash
# Create backup script
cat > backup_db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/nidps"
mkdir -p $BACKUP_DIR
pg_dump nidps_db | gzip > $BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S).sql.gz
# Keep only last 30 days
find $BACKUP_DIR -mtime +30 -delete
EOF

# Schedule daily backups
crontab -e
# Add: 0 2 * * * /path/to/backup_db.sh
```

### 3. Logging and Monitoring

#### Configure Log Rotation
```bash
cat > /etc/logrotate.d/nidps << 'EOF'
/path/to/sdn-nidps-project/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 nidps nidps
}
EOF
```

#### Install Prometheus Monitoring
```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.30.0/prometheus-2.30.0.linux-amd64.tar.gz
tar xvfz prometheus-2.30.0.linux-amd64.tar.gz
cd prometheus-2.30.0.linux-amd64

# Configure Prometheus
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'nidps'
    static_configs:
      - targets: ['localhost:8000']
EOF

# Start Prometheus
./prometheus --config.file=prometheus.yml
```

### 4. Load Balancing (Multi-Instance)

#### Setup Nginx as Reverse Proxy
```bash
sudo apt-get install nginx

# Create Nginx configuration
sudo cat > /etc/nginx/sites-available/nidps << 'EOF'
upstream nidps_backend {
    server 127.0.0.1:5000;
    server 127.0.0.1:5001;
    server 127.0.0.1:5002;
}

server {
    listen 80;
    server_name nidps.example.com;

    location / {
        proxy_pass http://nidps_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/ws {
        proxy_pass http://nidps_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/nidps /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

## Docker Deployment

### 1. Create Dockerfile
```dockerfile
FROM ubuntu:20.04

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    openvswitch-switch mininet suricata

# Copy project
COPY . .

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Expose ports
EXPOSE 6653 5000 8080

# Start services
CMD ["bash", "-c", "ryu-manager src/controller/sdn_controller.py & python3 src/dashboard/app.py"]
```

### 2. Build and Run
```bash
# Build image
docker build -t sdn-nidps:latest .

# Run container
docker run -p 6653:6653 -p 5000:5000 -p 8080:8080 \
  -v /path/to/logs:/app/logs \
  -v /path/to/config:/app/config \
  sdn-nidps:latest
```

### 3. Docker Compose Setup
```yaml
version: '3.8'

services:
  controller:
    build: .
    ports:
      - "6653:6653"
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    environment:
      - PYTHONUNBUFFERED=1

  dashboard:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    depends_on:
      - controller

  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: nidps_db
      POSTGRES_USER: nidps
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## Kubernetes Deployment

### 1. Create Kubernetes Manifests

**Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sdn-nidps
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sdn-nidps
  template:
    metadata:
      labels:
        app: sdn-nidps
    spec:
      containers:
      - name: controller
        image: sdn-nidps:latest
        ports:
        - containerPort: 6653
        resources:
          requests:
            cpu: "500m"
            memory: "1Gi"
          limits:
            cpu: "1000m"
            memory: "2Gi"
```

**Service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: sdn-nidps-service
spec:
  type: LoadBalancer
  selector:
    app: sdn-nidps
  ports:
  - protocol: TCP
    port: 80
    targetPort: 5000
```

### 2. Deploy to Kubernetes
```bash
# Create namespace
kubectl create namespace sdn-nidps

# Apply manifests
kubectl apply -f deployment.yaml -n sdn-nidps
kubectl apply -f service.yaml -n sdn-nidps

# Check status
kubectl get pods -n sdn-nidps
kubectl get svc -n sdn-nidps
```

## Troubleshooting

### Controller Won't Start
```bash
# Check if port 6653 is in use
netstat -tlnp | grep 6653

# Kill existing process
lsof -ti:6653 | xargs kill -9

# Restart controller
ryu-manager src/controller/sdn_controller.py
```

### Dashboard Not Accessible
```bash
# Check if port 5000 is listening
netstat -tlnp | grep 5000

# Check logs
tail -f logs/dashboard.log

# Restart dashboard
pkill -f "python3 src/dashboard/app.py"
python3 src/dashboard/app.py
```

### Database Connection Issues
```bash
# Test database connection
python3 -c "from src.database.database import db; print(db.session.execute('SELECT 1'))"

# Check database status
sudo systemctl status postgresql

# Restart database
sudo systemctl restart postgresql
```

### Memory Leaks
```bash
# Monitor memory usage
watch -n 1 'ps aux | grep python3'

# Use memory profiler
pip3 install memory-profiler
python3 -m memory_profiler src/controller/sdn_controller.py
```

## Performance Optimization

### 1. Tune System Parameters
```bash
# Increase file descriptors
ulimit -n 65536

# Tune network parameters
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.core.somaxconn=4096
```

### 2. Database Optimization
```sql
-- Create indexes
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_severity ON alerts(severity);

-- Analyze tables
ANALYZE alerts;
ANALYZE flow_rules;
```

### 3. Application Tuning
```python
# In src/utils/config.py
CACHE_TTL = 300  # Cache responses for 5 minutes
MAX_POOL_SIZE = 20
BATCH_SIZE = 100
```

## Monitoring Checklist
- [ ] CPU usage < 80%
- [ ] Memory usage < 85%
- [ ] Disk usage < 90%
- [ ] Database response time < 100ms
- [ ] API response time < 200ms
- [ ] Alert processing < 1 second
- [ ] No error logs in past hour
- [ ] All services running
- [ ] Backups completed successfully
- [ ] Log rotation working

## Backup and Recovery

### Backup Strategy
```bash
# Daily backups
0 2 * * * /usr/local/bin/backup_nidps.sh

# Weekly full backup
0 3 * * 0 /usr/local/bin/backup_nidps_full.sh

# Monthly archive
0 4 1 * * /usr/local/bin/archive_nidps.sh
```

### Recovery Procedure
```bash
# Restore from backup
psql nidps_db < /backups/nidps/backup_latest.sql

# Verify recovery
psql nidps_db -c "SELECT COUNT(*) FROM alerts;"

# Restart services
systemctl restart nidps-controller nidps-dashboard
```

## Upgrade Procedure
```bash
# Backup current installation
cp -r /app /app-backup-$(date +%Y%m%d)

# Pull latest code
git pull origin main

# Run migrations
python3 migrate.py

# Test deployment
pytest src/tests/

# Deploy
systemctl restart nidps-controller nidps-dashboard

# Verify
curl http://localhost:5000/api/status
```
