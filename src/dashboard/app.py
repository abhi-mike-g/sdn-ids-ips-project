from flask import Flask, render_template, request
from flask_cors import CORS
from .api import api_bp
from .websocket import socketio
from ..utils.logger import setup_logger
from ..utils.config import config

logger = setup_logger('dashboard')

def create_app():
    """Create Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sdn-nidps-secret-key-change-in-production'
    
    # Enable CORS
    CORS(app)
    
    # Initialize SocketIO
    socketio.init_app(app, cors_allowed_origins="*")
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Routes
    @app.route('/')
    def index():
        """Dashboard home"""
        return render_template('dashboard.html')
    
    @app.route('/topology')
    def topology():
        """Network topology view"""
        return render_template('topology.html')
    
    @app.route('/logs')
    def logs():
        """Alert logs view"""
        return render_template('logs.html')
    
    @app.route('/metrics')
    def metrics():
        """System metrics view"""
        return render_template('metrics.html')
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not found'}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal error: {error}")
        return {'error': 'Internal server error'}, 500
    
    logger.info("Dashboard application created")
    return app

def run_dashboard():
    """Run dashboard server"""
    app = create_app()
    host = config.get('dashboard.host', '0.0.0.0')
    port = config.get('dashboard.port', 5000)
    debug = config.get('dashboard.debug', True)
    
    logger.info(f"Starting dashboard on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_dashboard()
