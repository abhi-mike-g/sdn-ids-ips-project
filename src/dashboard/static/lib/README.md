# External Libraries

This directory contains external JavaScript libraries used by the dashboard.

## Libraries

### Chart.js
**Version**: 4.3.0
**Purpose**: Interactive data visualization and charting
**Source**: https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js

Used for:
- Real-time threat timelines
- CPU/Memory usage graphs
- Network traffic visualization
- Attack type distribution charts

**Installation**:
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js"></script>
```

### Vis Network
**Version**: 4.21.0
**Purpose**: Interactive network visualization
**Source**: https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js
**CSS**: https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css

Used for:
- Network topology visualization
- Switch and host representation
- Link visualization
- Real-time topology updates

**Installation**:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet" type="text/css" />
```

### Socket.IO
**Version**: 4.5.4
**Purpose**: Real-time bidirectional communication
**Source**: https://cdn.socket.io/4.5.4/socket.io.min.js

Used for:
- Real-time alert push notifications
- Live metrics updates
- Topology changes broadcasting
- WebSocket management

**Installation**:
```html
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
```

### Bootstrap
**Version**: 5.3.0
**Purpose**: Responsive UI framework
**Source**: https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css

Used for:
- Responsive layout
- UI components (buttons, forms, modals)
- Bootstrap utilities

**Installation**:
```html
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
```

### Font Awesome
**Version**: 6.4.0
**Purpose**: Icon library
**Source**: https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css

Used for:
- Dashboard icons
- Navigation icons
- Status indicators

**Installation**:
```html
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
```

## Local Library Files

To use local copies instead of CDN:

1. Download the libraries:
```bash
# Chart.js
wget https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js -O chart.js

# Vis Network
wget https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js -O vis-network.js
wget https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css -O vis-network.css
```

2. Update HTML to use local files:
```html
<script src="{{ url_for('static', filename='lib/chart.js') }}"></script>
<script src="{{ url_for('static', filename='lib/vis-network.js') }}"></script>
<link href="{{ url_for('static', filename='lib/vis-network.css') }}" rel="stylesheet">
```

## Version Management

Keep track of library versions:
- Chart.js: 4.3.0
- Vis Network: 4.21.0
- Socket.IO: 4.5.4
- Bootstrap: 5.3.0
- Font Awesome: 6.4.0

Update libraries quarterly or as needed for security patches.

## Browser Compatibility

Tested on:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Performance

Libraries are loaded from CDN for:
- Faster initial load (cached by browser)
- Reduced server bandwidth
- Automatic updates

For offline deployment, use local copies and implement cache busting with version numbers.

## License

All third-party libraries comply with their respective licenses:
- Chart.js: MIT
- Vis Network: Apache 2.0
- Socket.IO: MIT
- Bootstrap: MIT
- Font Awesome: CC BY 4.0 (icons)
