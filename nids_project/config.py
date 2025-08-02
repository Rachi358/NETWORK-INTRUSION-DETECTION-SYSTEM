"""
Configuration settings for Network Intrusion Detection System (NIDS)
"""
import os
from datetime import timedelta

class Config:
    """Base configuration class with common settings"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'nids-secret-key-2024'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'production'
    DEBUG = os.environ.get('DEBUG') or False
    
    # Database configuration
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///logs/detection_logs.db'
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ML Model configuration
    MODEL_DIR = 'models'
    DATASET_PATH = 'data/NSL-KDD'
    TRAINED_MODEL_PATH = os.path.join(MODEL_DIR, 'rf_model.joblib')
    SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')
    PCA_PATH = os.path.join(MODEL_DIR, 'pca.joblib')
    
    # Packet capture configuration
    INTERFACE = 'eth0'  # Network interface for packet capture
    CAPTURE_TIMEOUT = 5  # Timeout in seconds
    MAX_PACKET_SIZE = 65535
    
    # Real-time monitoring settings
    PREDICTION_BATCH_SIZE = 100
    ALERT_THRESHOLD = 0.8  # Confidence threshold for alerts
    LOG_RETENTION_DAYS = 30
    
    # Security settings
    CORS_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']
    SESSION_TIMEOUT = timedelta(hours=24)
    
    # Email/Alert configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER') or 'smtp.gmail.com'
    SMTP_PORT = int(os.environ.get('SMTP_PORT') or 587)
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
    
    # Telegram Bot configuration (optional)
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')
    
    # Feature engineering settings
    FEATURE_COLUMNS = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]
    
    # Attack type mappings
    ATTACK_TYPES = {
        'normal': 0,
        'dos': 1,
        'probe': 2,
        'r2l': 3,
        'u2r': 4
    }
    
    ATTACK_NAMES = {
        0: 'Normal',
        1: 'Denial of Service (DoS)',
        2: 'Probe',
        3: 'Remote to Local (R2L)',
        4: 'User to Root (U2R)'
    }

class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    FLASK_ENV = 'development'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///logs/dev_detection_logs.db'

class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    FLASK_ENV = 'production'
    # Use PostgreSQL in production
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                             'postgresql://user:password@localhost/nids_production'

class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}