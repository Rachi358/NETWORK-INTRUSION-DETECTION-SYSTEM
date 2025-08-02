"""
Database handler for Network Intrusion Detection System
Manages detection logs, model metrics, and system analytics
"""

from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_
import json

db = SQLAlchemy()

class DetectionLog(db.Model):
    """Model for storing intrusion detection results"""
    
    __tablename__ = 'detection_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)  # IPv6 compatible
    destination_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=False)
    packet_size = db.Column(db.Integer, nullable=True)
    
    # Prediction results
    prediction = db.Column(db.Integer, nullable=False)  # 0=normal, 1-4=attack types
    confidence = db.Column(db.Float, nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    
    # Additional packet features
    features_json = db.Column(db.Text, nullable=True)  # JSON string of features
    
    # Alert status
    is_alert = db.Column(db.Boolean, default=False)
    alert_sent = db.Column(db.Boolean, default=False)
    
    def __init__(self, source_ip, destination_ip, protocol, prediction, 
                 confidence, attack_type, source_port=None, destination_port=None,
                 packet_size=None, features=None, is_alert=False):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol
        self.packet_size = packet_size
        self.prediction = prediction
        self.confidence = confidence
        self.attack_type = attack_type
        self.features_json = json.dumps(features) if features else None
        self.is_alert = is_alert
    
    def to_dict(self):
        """Convert detection log to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'prediction': self.prediction,
            'confidence': self.confidence,
            'attack_type': self.attack_type,
            'is_alert': self.is_alert,
            'alert_sent': self.alert_sent,
            'features': json.loads(self.features_json) if self.features_json else None
        }

class ModelMetrics(db.Model):
    """Model for storing ML model performance metrics"""
    
    __tablename__ = 'model_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(100), nullable=False)
    accuracy = db.Column(db.Float, nullable=False)
    precision = db.Column(db.Float, nullable=False)
    recall = db.Column(db.Float, nullable=False)
    f1_score = db.Column(db.Float, nullable=False)
    training_time = db.Column(db.Float, nullable=True)
    dataset_size = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    
    def __init__(self, model_name, accuracy, precision, recall, f1_score,
                 training_time=None, dataset_size=None, is_active=False):
        self.model_name = model_name
        self.accuracy = accuracy
        self.precision = precision
        self.recall = recall
        self.f1_score = f1_score
        self.training_time = training_time
        self.dataset_size = dataset_size
        self.is_active = is_active
    
    def to_dict(self):
        """Convert model metrics to dictionary"""
        return {
            'id': self.id,
            'model_name': self.model_name,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'training_time': self.training_time,
            'dataset_size': self.dataset_size,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }

class SystemStats(db.Model):
    """Model for storing system statistics and analytics"""
    
    __tablename__ = 'system_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    total_packets = db.Column(db.Integer, default=0)
    normal_packets = db.Column(db.Integer, default=0)
    attack_packets = db.Column(db.Integer, default=0)
    cpu_usage = db.Column(db.Float, nullable=True)
    memory_usage = db.Column(db.Float, nullable=True)
    
    def to_dict(self):
        """Convert system stats to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'total_packets': self.total_packets,
            'normal_packets': self.normal_packets,
            'attack_packets': self.attack_packets,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage
        }

class DatabaseHandler:
    """Handler class for database operations"""
    
    def __init__(self, app=None):
        self.db = db
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize database with Flask app"""
        self.db.init_app(app)
        with app.app_context():
            self.db.create_all()
    
    def log_detection(self, source_ip, destination_ip, protocol, prediction,
                     confidence, attack_type, **kwargs):
        """Log a detection result to database"""
        try:
            detection = DetectionLog(
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                prediction=prediction,
                confidence=confidence,
                attack_type=attack_type,
                **kwargs
            )
            self.db.session.add(detection)
            self.db.session.commit()
            return detection.id
        except Exception as e:
            self.db.session.rollback()
            raise e
    
    def get_recent_detections(self, limit=100, hours=24):
        """Get recent detection logs"""
        since = datetime.utcnow() - timedelta(hours=hours)
        return DetectionLog.query.filter(
            DetectionLog.timestamp >= since
        ).order_by(DetectionLog.timestamp.desc()).limit(limit).all()
    
    def get_attack_statistics(self, hours=24):
        """Get attack statistics for the specified time period"""
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Total counts
        total_count = DetectionLog.query.filter(
            DetectionLog.timestamp >= since
        ).count()
        
        # Attack type distribution
        attack_stats = self.db.session.query(
            DetectionLog.attack_type,
            func.count(DetectionLog.id).label('count')
        ).filter(
            DetectionLog.timestamp >= since
        ).group_by(DetectionLog.attack_type).all()
        
        # Hourly distribution
        hourly_stats = self.db.session.query(
            func.date_trunc('hour', DetectionLog.timestamp).label('hour'),
            func.count(DetectionLog.id).label('count')
        ).filter(
            DetectionLog.timestamp >= since
        ).group_by('hour').order_by('hour').all()
        
        return {
            'total_count': total_count,
            'attack_distribution': [{'type': stat[0], 'count': stat[1]} for stat in attack_stats],
            'hourly_distribution': [{'hour': stat[0].isoformat(), 'count': stat[1]} for stat in hourly_stats]
        }
    
    def save_model_metrics(self, model_name, accuracy, precision, recall, f1_score,
                          training_time=None, dataset_size=None, set_active=False):
        """Save model performance metrics"""
        try:
            if set_active:
                # Deactivate all other models
                ModelMetrics.query.update({'is_active': False})
            
            metrics = ModelMetrics(
                model_name=model_name,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1_score,
                training_time=training_time,
                dataset_size=dataset_size,
                is_active=set_active
            )
            self.db.session.add(metrics)
            self.db.session.commit()
            return metrics.id
        except Exception as e:
            self.db.session.rollback()
            raise e
    
    def get_model_comparison(self):
        """Get comparison of all model performances"""
        return ModelMetrics.query.order_by(ModelMetrics.accuracy.desc()).all()
    
    def update_system_stats(self, total_packets=0, normal_packets=0, 
                           attack_packets=0, cpu_usage=None, memory_usage=None):
        """Update system statistics"""
        try:
            stats = SystemStats(
                total_packets=total_packets,
                normal_packets=normal_packets,
                attack_packets=attack_packets,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage
            )
            self.db.session.add(stats)
            self.db.session.commit()
            return stats.id
        except Exception as e:
            self.db.session.rollback()
            raise e
    
    def cleanup_old_logs(self, retention_days=30):
        """Clean up old detection logs based on retention policy"""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        deleted_count = DetectionLog.query.filter(
            DetectionLog.timestamp < cutoff_date
        ).delete()
        
        self.db.session.commit()
        return deleted_count
    
    def get_dashboard_data(self):
        """Get data for dashboard display"""
        # Recent 24 hours statistics
        recent_stats = self.get_attack_statistics(hours=24)
        
        # Last 7 days trend
        week_ago = datetime.utcnow() - timedelta(days=7)
        daily_stats = self.db.session.query(
            func.date(DetectionLog.timestamp).label('date'),
            func.count(DetectionLog.id).label('total'),
            func.sum(func.case([(DetectionLog.prediction == 0, 1)], else_=0)).label('normal'),
            func.sum(func.case([(DetectionLog.prediction > 0, 1)], else_=0)).label('attacks')
        ).filter(
            DetectionLog.timestamp >= week_ago
        ).group_by('date').order_by('date').all()
        
        # Active alerts count
        active_alerts = DetectionLog.query.filter(
            and_(DetectionLog.is_alert == True, DetectionLog.alert_sent == False)
        ).count()
        
        # Model performance
        active_model = ModelMetrics.query.filter_by(is_active=True).first()
        
        return {
            'recent_stats': recent_stats,
            'daily_trend': [
                {
                    'date': stat[0].isoformat(),
                    'total': stat[1],
                    'normal': stat[2] or 0,
                    'attacks': stat[3] or 0
                } for stat in daily_stats
            ],
            'active_alerts': active_alerts,
            'active_model': active_model.to_dict() if active_model else None
        }