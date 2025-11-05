"""
Dashboard package - Web-based monitoring interface

Handles:
- REST API endpoints
- WebSocket real-time updates
- Web UI serving
- Data visualization
- User interactions
"""

from .app import create_app, socketio
from .api import api_bp

__all__ = [
    'create_app',
    'socketio',
    'api_bp'
]
