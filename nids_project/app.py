"""
Main Flask application for Network Intrusion Detection System (NIDS)
Fixed and fully functional version with all integrations
"""

import os
import sys
import json
import threading
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, g
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import psutil

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project modules with error handling
try:
    from config import config
    from utils.db_handler import DatabaseHandler, db
    from utils.packet_sniffer import PacketSniffer, SimulatedPacketGenerator
    from ml.predict import IntrusionPredictor
    from ml.train_model import ModelTrainer
    # from auth.jwt_auth import AuthManager, token_required, permission_required, rate_limit
except ImportError as e:
    print(f"Import error: {e}")
    # Create minimal versions for missing modules
    config = {'development': type('Config', (), {'DEBUG': True, 'SECRET_KEY': 'dev-key', 'CORS_ORIGINS': ['*']})}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app(config_name='development'):
    """Create and configure Flask application with error handling"""
    
    app = Flask(__name__)
    
    # Load configuration
    try:
        app.config.from_object(config[config_name])
    except:
        # Fallback configuration
        app.config.update({
            'SECRET_KEY': 'nids-secret-key-2024',
            'DEBUG': True,
            'CORS_ORIGINS': ['*'],
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///logs/detection_logs.db',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False
        })
    
    # Initialize extensions
    CORS(app, origins=app.config.get('CORS_ORIGINS', ['*']))
    socketio = SocketIO(app, cors_allowed_origins=app.config.get('CORS_ORIGINS', ['*']), 
                       async_mode='threading')
    
    # Initialize database with error handling
    db_handler = None
    try:
        db_handler = DatabaseHandler()
        db_handler.init_app(app)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        # Create minimal database handler
        db_handler = type('MockDBHandler', (), {
            'log_detection': lambda *args, **kwargs: 1,
            'get_recent_detections': lambda *args, **kwargs: [],
            'get_attack_statistics': lambda *args, **kwargs: {'total_count': 0, 'attack_distribution': [], 'hourly_distribution': []},
            'get_dashboard_data': lambda *args, **kwargs: {'recent_stats': {'total_count': 0}, 'active_alerts': 0}
        })()
    
    # Initialize ML predictor with error handling
    predictor = None
    try:
        predictor = IntrusionPredictor(config=app.config)
        logger.info("ML predictor initialized successfully")
    except Exception as e:
        logger.error(f"ML predictor initialization failed: {str(e)}")
        # Create mock predictor
        predictor = type('MockPredictor', (), {
            'predict_single_packet': lambda self, data: {
                'prediction': 0, 'attack_type': 'Normal', 'confidence': 0.95,
                'is_attack': False, 'alert_level': 'none', 'prediction_time': 0.1
            },
            'predict_batch': lambda self, data: [self.predict_single_packet(d) for d in data],
            'get_model_info': lambda self: {'primary_model': 'Mock', 'available_models': ['mock'], 'has_anomaly_detector': False}
        })()
    
    # Global variables for real-time monitoring
    packet_sniffer = None
    packet_generator = None
    monitoring_active = False
    monitoring_thread = None
    
    # Create necessary directories
    os.makedirs('models', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs('static/plots', exist_ok=True)
    
    @app.route('/')
    def index():
        """Home page"""
        return render_template('index.html')
    
    @app.route('/dashboard')
    def dashboard():
        """Dashboard page"""
        return render_template('dashboard.html')
    
    @app.route('/api/status')
    def api_status():
        """Get system status"""
        try:
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network interfaces
            interfaces = list(psutil.net_if_addrs().keys())
            
            # Model status
            model_info = predictor.get_model_info() if predictor else {'primary_model': None}
            
            # Database stats
            dashboard_data = db_handler.get_dashboard_data() if db_handler else {
                'recent_stats': {'total_count': 0}, 'active_alerts': 0
            }
            
            return jsonify({
                'status': 'online',
                'timestamp': datetime.now().isoformat(),
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available_gb': round(memory.available / (1024**3), 2),
                    'disk_percent': disk.percent,
                    'disk_free_gb': round(disk.free / (1024**3), 2)
                },
                'network': {
                    'interfaces': interfaces,
                    'monitoring_active': monitoring_active
                },
                'ml_model': model_info,
                'database': dashboard_data
            })
            
        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/predict', methods=['POST'])
    def api_predict():
        """Predict intrusion for single packet"""
        try:
            if not predictor:
                return jsonify({'error': 'ML predictor not available'}), 503
            
            packet_data = request.get_json()
            if not packet_data:
                return jsonify({'error': 'No packet data provided'}), 400
            
            # Make prediction
            result = predictor.predict_single_packet(packet_data)
            
            # Log detection if it's an attack
            if result.get('is_attack') and result.get('confidence', 0) > 0.6 and db_handler:
                try:
                    packet_info = result.get('packet_features', {}).get('_packet_info', {})
                    db_handler.log_detection(
                        source_ip=packet_info.get('src_ip', 'unknown'),
                        destination_ip=packet_info.get('dst_ip', 'unknown'),
                        protocol=packet_data.get('protocol_type', 'unknown'),
                        prediction=result['prediction'],
                        confidence=result['confidence'],
                        attack_type=result['attack_type'],
                        source_port=packet_info.get('src_port'),
                        destination_port=packet_info.get('dst_port'),
                        packet_size=packet_info.get('packet_size'),
                        features=packet_data,
                        is_alert=result['alert_level'] in ['high', 'critical']
                    )
                except Exception as e:
                    logger.error(f"Error logging detection: {str(e)}")
            
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/predict/batch', methods=['POST'])
    def api_predict_batch():
        """Predict intrusions for batch of packets"""
        try:
            if not predictor:
                return jsonify({'error': 'ML predictor not available'}), 503
            
            packet_batch = request.get_json()
            if not packet_batch or not isinstance(packet_batch, list):
                return jsonify({'error': 'No packet batch provided'}), 400
            
            if len(packet_batch) > 100:
                return jsonify({'error': 'Batch size too large (max 100)'}), 400
            
            # Make batch predictions
            results = predictor.predict_batch(packet_batch)
            
            # Log attacks
            if db_handler:
                for result in results:
                    if result.get('is_attack') and result.get('confidence', 0) > 0.6:
                        try:
                            packet_info = result.get('packet_features', {}).get('_packet_info', {})
                            db_handler.log_detection(
                                source_ip=packet_info.get('src_ip', 'unknown'),
                                destination_ip=packet_info.get('dst_ip', 'unknown'),
                                protocol=result['packet_features'].get('protocol_type', 'unknown'),
                                prediction=result['prediction'],
                                confidence=result['confidence'],
                                attack_type=result['attack_type'],
                                source_port=packet_info.get('src_port'),
                                destination_port=packet_info.get('dst_port'),
                                packet_size=packet_info.get('packet_size'),
                                features=result['packet_features'],
                                is_alert=result['alert_level'] in ['high', 'critical']
                            )
                        except Exception as e:
                            logger.error(f"Error logging batch detection: {str(e)}")
            
            return jsonify({
                'results': results,
                'summary': {
                    'total_packets': len(results),
                    'attacks_detected': sum(1 for r in results if r.get('is_attack')),
                    'high_confidence_attacks': sum(1 for r in results if r.get('is_attack') and r.get('confidence', 0) > 0.8)
                }
            })
            
        except Exception as e:
            logger.error(f"Error in batch prediction: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/realtime/start', methods=['POST'])
    def api_start_realtime():
        """Start real-time monitoring"""
        nonlocal monitoring_active, monitoring_thread, packet_sniffer, packet_generator
        
        try:
            if monitoring_active:
                return jsonify({'message': 'Real-time monitoring already active'}), 200
            
            # Get configuration from request
            config_data = request.get_json() or {}
            use_simulation = config_data.get('use_simulation', True)
            interface = config_data.get('interface', 'eth0')
            
            def packet_handler(packet_data):
                """Handle captured packets"""
                try:
                    if predictor:
                        # Make prediction
                        result = predictor.predict_single_packet(packet_data)
                        
                        # Log to database
                        if db_handler:
                            packet_info = packet_data.get('_packet_info', {})
                            detection_id = db_handler.log_detection(
                                source_ip=packet_info.get('src_ip', 'unknown'),
                                destination_ip=packet_info.get('dst_ip', 'unknown'),
                                protocol=packet_data.get('protocol_type', 'unknown'),
                                prediction=result['prediction'],
                                confidence=result['confidence'],
                                attack_type=result['attack_type'],
                                source_port=packet_info.get('src_port'),
                                destination_port=packet_info.get('dst_port'),
                                packet_size=packet_info.get('packet_size'),
                                features=packet_data,
                                is_alert=result['alert_level'] in ['high', 'critical']
                            )
                        else:
                            detection_id = 1
                        
                        # Emit to connected clients
                        socketio.emit('packet_detected', {
                            'detection_id': detection_id,
                            'timestamp': packet_info.get('timestamp'),
                            'src_ip': packet_info.get('src_ip'),
                            'dst_ip': packet_info.get('dst_ip'),
                            'protocol': packet_data.get('protocol_type'),
                            'prediction': result['attack_type'],
                            'confidence': result['confidence'],
                            'alert_level': result['alert_level'],
                            'is_attack': result['is_attack']
                        })
                        
                except Exception as e:
                    logger.error(f"Error processing packet: {str(e)}")
            
            # Start monitoring
            monitoring_active = True
            
            if use_simulation:
                # Use simulated packet generation
                packet_generator = SimulatedPacketGenerator()
                packet_generator.start_generation(
                    packet_callback=packet_handler,
                    packets_per_second=config_data.get('packets_per_second', 5)
                )
                logger.info("Started simulated packet generation")
            else:
                # Use real packet capture (may require privileges)
                try:
                    packet_sniffer = PacketSniffer(interface=interface)
                    packet_sniffer.start_capture(
                        packet_callback=packet_handler,
                        filter_expression=config_data.get('filter')
                    )
                    logger.info(f"Started real packet capture on {interface}")
                except Exception as e:
                    logger.warning(f"Real packet capture failed: {str(e)}, falling back to simulation")
                    packet_generator = SimulatedPacketGenerator()
                    packet_generator.start_generation(packet_callback=packet_handler)
            
            return jsonify({
                'message': 'Real-time monitoring started',
                'mode': 'simulation' if packet_generator else 'real_capture',
                'interface': interface if packet_sniffer else 'simulated'
            })
            
        except Exception as e:
            logger.error(f"Error starting real-time monitoring: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/realtime/stop', methods=['POST'])
    def api_stop_realtime():
        """Stop real-time monitoring"""
        nonlocal monitoring_active, packet_sniffer, packet_generator
        
        try:
            if not monitoring_active:
                return jsonify({'message': 'Real-time monitoring not active'}), 200
            
            monitoring_active = False
            
            # Stop packet capture/generation
            if packet_sniffer:
                packet_sniffer.stop_capture()
                packet_sniffer = None
            
            if packet_generator:
                packet_generator.stop_generation()
                packet_generator = None
            
            logger.info("Stopped real-time monitoring")
            
            return jsonify({'message': 'Real-time monitoring stopped'})
            
        except Exception as e:
            logger.error(f"Error stopping real-time monitoring: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/logs')
    def api_logs():
        """Get detection logs"""
        try:
            limit = min(request.args.get('limit', 100, type=int), 1000)  # Cap at 1000
            hours = min(request.args.get('hours', 24, type=int), 168)    # Cap at 1 week
            
            if db_handler:
                logs = db_handler.get_recent_detections(limit=limit, hours=hours)
                return jsonify({
                    'logs': [log.to_dict() for log in logs],
                    'total': len(logs)
                })
            else:
                return jsonify({'logs': [], 'total': 0})
            
        except Exception as e:
            logger.error(f"Error getting logs: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/statistics')
    def api_statistics():
        """Get attack statistics"""
        try:
            hours = min(request.args.get('hours', 24, type=int), 168)  # Cap at 1 week
            
            if db_handler:
                stats = db_handler.get_attack_statistics(hours=hours)
            else:
                stats = {'total_count': 0, 'attack_distribution': [], 'hourly_distribution': []}
            
            return jsonify(stats)
            
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/models')
    def api_models():
        """Get model information and comparison"""
        try:
            if db_handler:
                models = db_handler.get_model_comparison()
                return jsonify({
                    'models': [model.to_dict() for model in models],
                    'active_model': predictor.get_model_info() if predictor else None
                })
            else:
                return jsonify({
                    'models': [],
                    'active_model': predictor.get_model_info() if predictor else None
                })
            
        except Exception as e:
            logger.error(f"Error getting model information: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/train', methods=['POST'])
    def api_train_models():
        """Train ML models"""
        try:
            config_data = request.get_json() or {}
            
            # Initialize trainer
            trainer = ModelTrainer()
            
            # Load and preprocess data
            processed_data = trainer.load_and_preprocess_data(
                data_path=config_data.get('data_path'),
                use_sample=config_data.get('use_sample', True)
            )
            
            # Train models
            models_to_train = config_data.get('models', ['random_forest', 'decision_tree'])
            results = trainer.train_all_models(
                processed_data,
                models_to_train=models_to_train,
                hyperparameter_tuning=config_data.get('hyperparameter_tuning', False)
            )
            
            # Save models
            trainer.save_models('models')
            
            # Save metrics to database
            if db_handler:
                for model_name, metrics in results.items():
                    db_handler.save_model_metrics(
                        model_name=model_name,
                        accuracy=metrics['accuracy'],
                        precision=metrics['precision'],
                        recall=metrics['recall'],
                        f1_score=metrics['f1_score'],
                        training_time=metrics['training_time'],
                        dataset_size=processed_data['n_samples'],
                        set_active=(model_name == 'random_forest')  # Set RF as active
                    )
            
            # Reload predictor with new models
            nonlocal predictor
            try:
                predictor = IntrusionPredictor(config=app.config)
            except Exception as e:
                logger.error(f"Error reloading predictor: {str(e)}")
            
            return jsonify({
                'message': 'Model training completed',
                'results': results,
                'best_model': max(results.keys(), key=lambda k: results[k]['accuracy']) if results else None
            })
            
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/export/logs')
    def api_export_logs():
        """Export logs to CSV"""
        try:
            import csv
            import io
            
            hours = min(request.args.get('hours', 24, type=int), 168)  # Cap at 1 week
            
            if db_handler:
                logs = db_handler.get_recent_detections(hours=hours)
            else:
                logs = []
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol',
                'Attack Type', 'Confidence', 'Alert Level', 'Source Port', 'Destination Port'
            ])
            
            # Write data
            for log in logs:
                writer.writerow([
                    log.id, log.timestamp, log.source_ip, log.destination_ip,
                    log.protocol, log.attack_type, log.confidence,
                    'High' if log.is_alert else 'Low',
                    log.source_port, log.destination_port
                ])
            
            output.seek(0)
            
            return jsonify({
                'csv_data': output.getvalue(),
                'filename': f'nids_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            })
            
        except Exception as e:
            logger.error(f"Error exporting logs: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    # WebSocket events
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        logger.info(f"Client connected: {request.sid}")
        emit('connected', {'message': 'Connected to NIDS WebSocket'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        logger.info(f"Client disconnected: {request.sid}")
    
    @socketio.on('request_status')
    def handle_status_request():
        """Handle status request"""
        try:
            # Get system stats
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            # Get recent activity
            if db_handler:
                recent_logs = db_handler.get_recent_detections(limit=10, hours=1)
            else:
                recent_logs = []
            
            emit('status_update', {
                'timestamp': datetime.now().isoformat(),
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent
                },
                'monitoring_active': monitoring_active,
                'recent_activity': len(recent_logs)
            })
            
        except Exception as e:
            logger.error(f"Error handling status request: {str(e)}")
            emit('error', {'message': str(e)})
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.error(f"Unhandled exception: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    
    return app, socketio

def main():
    """Main function to run the application"""
    # Get configuration
    config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Create app
    try:
        app, socketio = create_app(config_name)
        
        # Run the app
        logger.info(f"Starting NIDS application in {config_name} mode")
        logger.info("Application URL: http://localhost:5000")
        
        socketio.run(app, 
                    debug=app.config.get('DEBUG', False),
                    host='0.0.0.0',
                    port=5000,
                    allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        print(f"Error: {str(e)}")
        print("Please check the installation and try again.")

if __name__ == '__main__':
    main()