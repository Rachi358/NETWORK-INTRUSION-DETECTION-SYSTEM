"""
JWT Authentication system with role-based access control for NIDS
Enterprise-grade security implementation
"""

import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app, g
from flask_sqlalchemy import SQLAlchemy
import secrets
import pyotp
import qrcode
import io
import base64
from typing import Dict, List, Optional, Tuple

db = SQLAlchemy()

class Role(db.Model):
    """User roles for RBAC"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    permissions = db.Column(db.JSON)  # List of permission strings
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, name, description, permissions=None):
        self.name = name
        self.description = description
        self.permissions = permissions or []

class User(db.Model):
    """User model with security features"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Security fields
    salt = db.Column(db.String(32), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 2FA fields
    totp_secret = db.Column(db.String(32))
    backup_codes = db.Column(db.JSON)  # List of backup codes
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    # Profile fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    role = db.relationship('Role', backref='users')
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __init__(self, username, email, password, first_name=None, last_name=None, role_id=None):
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.role_id = role_id
        self.salt = secrets.token_hex(16)
        self.set_password(password)
        self.generate_backup_codes()
    
    def set_password(self, password: str):
        """Set password with salt and bcrypt"""
        password_bytes = (password + self.salt).encode('utf-8')
        self.password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password: str) -> bool:
        """Check password against hash"""
        if self.is_locked():
            return False
        
        password_bytes = (password + self.salt).encode('utf-8')
        is_valid = bcrypt.checkpw(password_bytes, self.password_hash.encode('utf-8'))
        
        if not is_valid:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
        else:
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
            db.session.commit()
        
        return is_valid
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def generate_totp_secret(self) -> str:
        """Generate TOTP secret for 2FA"""
        self.totp_secret = pyotp.random_base32()
        db.session.commit()
        return self.totp_secret
    
    def get_totp_uri(self) -> str:
        """Get TOTP URI for QR code"""
        if not self.totp_secret:
            self.generate_totp_secret()
        
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name="NIDS Security System"
        )
    
    def verify_totp(self, token: str) -> bool:
        """Verify TOTP token"""
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self) -> List[str]:
        """Generate backup codes for 2FA"""
        codes = [secrets.token_hex(4).upper() for _ in range(10)]
        # Hash the codes before storing
        hashed_codes = [bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode() for code in codes]
        self.backup_codes = hashed_codes
        db.session.commit()
        return codes  # Return unhashed codes for user
    
    def use_backup_code(self, code: str) -> bool:
        """Use a backup code for 2FA"""
        if not self.backup_codes:
            return False
        
        for i, hashed_code in enumerate(self.backup_codes):
            if bcrypt.checkpw(code.encode(), hashed_code.encode()):
                # Remove used code
                self.backup_codes.pop(i)
                db.session.commit()
                return True
        
        return False
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        if not self.role or not self.role.permissions:
            return False
        return permission in self.role.permissions
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role.name if self.role else None,
            'mfa_enabled': self.mfa_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }

class SessionToken(db.Model):
    """Session tokens for tracking active sessions"""
    __tablename__ = 'session_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_hash = db.Column(db.String(128), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='sessions')

class AuthManager:
    """Authentication manager with enterprise features"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize authentication system"""
        db.init_app(app)
        self.create_default_roles()
    
    def create_default_roles(self):
        """Create default roles and admin user"""
        with self.app.app_context():
            db.create_all()
            
            # Create default roles
            roles_data = [
                {
                    'name': 'admin',
                    'description': 'Full system access',
                    'permissions': [
                        'read_dashboard', 'write_dashboard', 'manage_users',
                        'manage_models', 'start_monitoring', 'stop_monitoring',
                        'export_data', 'view_logs', 'manage_system'
                    ]
                },
                {
                    'name': 'analyst',
                    'description': 'Security analyst access',
                    'permissions': [
                        'read_dashboard', 'view_logs', 'export_data',
                        'start_monitoring', 'stop_monitoring'
                    ]
                },
                {
                    'name': 'viewer',
                    'description': 'Read-only access',
                    'permissions': ['read_dashboard', 'view_logs']
                }
            ]
            
            for role_data in roles_data:
                if not Role.query.filter_by(name=role_data['name']).first():
                    role = Role(**role_data)
                    db.session.add(role)
            
            # Create default admin user
            admin_role = Role.query.filter_by(name='admin').first()
            if not User.query.filter_by(username='admin').first():
                admin_user = User(
                    username='admin',
                    email='admin@nids.local',
                    password='admin123',  # Should be changed on first login
                    first_name='System',
                    last_name='Administrator',
                    role_id=admin_role.id
                )
                db.session.add(admin_user)
            
            db.session.commit()
    
    def generate_token(self, user: User, request_info: dict = None) -> Tuple[str, datetime]:
        """Generate JWT token with session tracking"""
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.name if user.role else None,
            'permissions': user.role.permissions if user.role else [],
            'exp': expires_at,
            'iat': datetime.utcnow(),
            'iss': 'NIDS-AUTH'
        }
        
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        # Store session
        session = SessionToken(
            user_id=user.id,
            token_hash=bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode(),
            expires_at=expires_at,
            ip_address=request_info.get('ip') if request_info else None,
            user_agent=request_info.get('user_agent') if request_info else None
        )
        db.session.add(session)
        db.session.commit()
        
        return token, expires_at
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # Check if session is still active
            user = User.query.get(payload['user_id'])
            if not user or not user.is_active:
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a specific token"""
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            token_hash = bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode()
            
            session = SessionToken.query.filter_by(
                user_id=payload['user_id'],
                token_hash=token_hash
            ).first()
            
            if session:
                session.is_active = False
                db.session.commit()
                return True
        except:
            pass
        
        return False
    
    def revoke_all_user_tokens(self, user_id: int) -> int:
        """Revoke all tokens for a user"""
        count = SessionToken.query.filter_by(user_id=user_id, is_active=True).update({'is_active': False})
        db.session.commit()
        return count

# Decorators for authentication and authorization
def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        auth_manager = current_app.extensions.get('auth_manager')
        payload = auth_manager.verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        # Set current user in g
        g.current_user_id = payload['user_id']
        g.current_user_permissions = payload.get('permissions', [])
        g.current_token = token
        
        return f(*args, **kwargs)
    
    return decorated

def permission_required(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user_permissions'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if permission not in g.current_user_permissions:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = User.query.get(g.current_user_id) if hasattr(g, 'current_user_id') else None
        
        if not user or not user.role or user.role.name != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    
    return decorated

# Rate limiting decorator
from functools import wraps
import redis
import time

def rate_limit(max_requests: int = 100, window: int = 3600, per_user: bool = True):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                # Use Redis for rate limiting if available
                redis_client = current_app.extensions.get('redis')
                if not redis_client:
                    return f(*args, **kwargs)  # Skip if Redis not available
                
                # Create key for rate limiting
                if per_user and hasattr(g, 'current_user_id'):
                    key = f"rate_limit:user:{g.current_user_id}:{f.__name__}"
                else:
                    key = f"rate_limit:ip:{request.remote_addr}:{f.__name__}"
                
                # Get current count
                current_requests = redis_client.get(key)
                if current_requests is None:
                    redis_client.setex(key, window, 1)
                    return f(*args, **kwargs)
                
                if int(current_requests) >= max_requests:
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': redis_client.ttl(key)
                    }), 429
                
                redis_client.incr(key)
                return f(*args, **kwargs)
                
            except Exception as e:
                # Log error but don't block request
                current_app.logger.error(f"Rate limiting error: {str(e)}")
                return f(*args, **kwargs)
        
        return decorated
    return decorator