
## 53. API Documentation (docs/API_DOCS.md)

```markdown
# SDN-NIDPS REST API Documentation

## Base URL
```
http://localhost:5000/api
```

## Authentication
Currently, the API uses no authentication. In production, implement:
- API Key authentication
- OAuth 2.0
- JWT tokens

## Endpoints

### System Status

#### GET /api/status
Get current system status.

**Response:**
```json
{
  "status": "running",
  "controller": "connected",
  "timestamp": "2025-01-01T12:00:00Z"
}
```

### Network Topology

#### GET /api/topology
Get network topology data.

**Response:**
```json
{
  "nodes": [
    {
      "id": "s1",
      "label": "S1",
      "type": "switch",
      "status": "active",
      "group": "switch"
    },
    {
      "id": "h1",
      "label": "10.0.0.1",
      "type": "host",
      "group": "host"
    }
  ],
  "edges": [
    {
      "from": "s1",
      "to": "s2",
      "label": "1-2"
    }
  ]
}
```

### Alerts

#### GET /api/alerts
Get recent alerts with optional filtering.

**Query Parameters:**
- `limit` (int): Number of alerts to return (default: 100)
- `severity` (int): Filter by severity (1-4, 1=Critical)
- `type` (string): Filter by alert type

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2025-01-01T12:00:00Z",
    "severity": 1,
    "type": "PORT_SCAN",
    "source_ip": "10.0.0.1",
    "destination_ip": "10.0.0.2",
    "source_port": 12345,
    "destination_port": 80,
    "protocol": "TCP",
    "signature": "Port Scan Detected",
    "description": "Multiple ports scanned",
    "blocked": true
  }
]
```

#### POST /api/block_ip
Block an IP address.

**Request Body:**
```json
{
  "ip": "10.0.0.1",
  "duration": 3600
}
```

**Response:**
```json
{
  "success": true,
  "ip": "10.0.0.1",
  "duration": 3600
}
```

#### POST /api/unblock_ip
Unblock an IP address.

**Request Body:**
```json
{
  "ip": "10.0.0.1"
}
```

**Response:**
```json
{
  "success": true,
  "ip": "10.0.0.1"
}
```

### Network Flows

#### GET /api/flows
Get active OpenFlow rules.

**Query Parameters:**
- `switch_id` (string): Filter by switch ID

**Response:**
```json
[
  {
    "id": 1,
    "switch_id": "1",
    "priority": 100,
    "match": "{\"eth_type\": 2048}",
    "actions": "[\"output:1\"]",
    "packet_count": 1000,
    "byte_count": 500000
  }
]
```

### System Metrics

#### GET /api/metrics
Get real-time system metrics.

**Response:**
```json
{
  "cpu_percent": 45.2,
  "memory_percent": 62.1,
  "disk_percent": 38.5,
  "network": {
    "bytes_sent": 1048576,
    "bytes_recv": 2097152
  }
}
```

#### GET /api/metrics/history
Get metrics history.

**Query Parameters:**
- `hours` (int): Number of hours of history (default: 1)

**Response:**
```json
[
  {
    "timestamp": "2025-01-01T12:00:00Z",
    "cpu_usage": 45.2,
    "memory_usage": 62.1,
    "active_flows": 150,
    "threats_detected": 5,
    "throughput_mbps": 125.5,
    "latency_ms": 45.2
  }
]
```

### Statistics

#### GET /api/statistics
Get overall system statistics.

**Response:**
```json
{
  "switches": 2,
  "hosts": 4,
  "links": 3,
  "total_flows": 150,
  "total_alerts": 25,
  "active_threats": 2,
  "blocked_ips": 5
}
```

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid request parameters"
}
```

### 404 Not Found
```json
{
  "error": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error"
}
```

### 503 Service Unavailable
```json
{
  "error": "Service temporarily unavailable"
}
```

## Rate Limiting
Currently not implemented. For production:
- Implement API rate limiting (e.g., 100 requests/minute)
- Use exponential backoff for retries
- Implement request queuing

## Pagination
For endpoints returning lists:
- Use `limit` parameter to control page size
- Use `offset` parameter for pagination
- Maximum limit: 1000 items

## WebSocket Events

### Connection
```javascript
socket.on('connect', function() {
  console.log('Connected to dashboard');
});
```

### New Alert
```javascript
socket.on('new_alert', function(data) {
  console.log('New alert:', data);
});
```

### Metrics Update
```javascript
socket.on('metrics_update', function(data) {
  console.log('Metrics updated:', data);
});
```

### Topology Update
```javascript
socket.on('topology_update', function(data) {
  console.log('Topology updated:', data);
});
```

## Example Requests

### cURL Examples

Get alerts:
```bash
curl http://localhost:5000/api/alerts?limit=10
```

Block IP:
```bash
curl -X POST http://localhost:5000/api/block_ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.1", "duration": 3600}'
```

Get metrics:
```bash
curl http://localhost:5000/api/metrics
```

### Python Example

```python
import requests

# Get alerts
response = requests.get('http://localhost:5000/api/alerts?limit=10')
alerts = response.json()

# Block IP
response = requests.post('http://localhost:5000/api/block_ip',
    json={'ip': '10.0.0.1', 'duration': 3600})
result = response.json()

# Get metrics
response = requests.get('http://localhost:5000/api/metrics')
metrics = response.json()
```

### JavaScript Example

```javascript
// Get alerts
fetch('/api/alerts?limit=10')
  .then(r => r.json())
  .then(alerts => console.log(alerts));

// Block IP
fetch('/api/block_ip', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({ip: '10.0.0.1', duration: 3600})
})
.then(r => r.json())
.then(result => console.log(result));

// Get metrics
fetch('/api/metrics')
  .then(r => r.json())
  .then(metrics => console.log(metrics));
```

## Versioning
Current API Version: 1.0
- Semantic versioning used
- Breaking changes increment major version
- New features increment minor version
- Bug fixes increment patch version

## Deprecation Policy
- Deprecated endpoints marked with `@deprecated`
- Deprecation notice provided 2 versions before removal
- Clients given 6 months to migrate

## Best Practices
1. Use appropriate HTTP methods (GET, POST, PUT, DELETE)
2. Handle rate limiting with exponential backoff
3. Implement connection pooling for performance
4. Cache responses when possible
5. Use pagination for large result sets
6. Implement retry logic for failed requests
7. Monitor API usage and performance
8. Keep API keys secure
```
