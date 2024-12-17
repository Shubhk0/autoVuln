from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime as dt
from datetime import timezone
from flask_login import UserMixin
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=dt.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Add relationship to scans
    scans = db.relationship('Scan', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    """Scan model for storing scan information"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, initializing, running, completed, error
    start_time = db.Column(db.DateTime(timezone=True), default=dt.now(timezone.utc))
    end_time = db.Column(db.DateTime(timezone=True))  # Renamed from completed_at for consistency
    error_message = db.Column(db.Text)
    progress = db.Column(db.Integer, default=0)  # Progress percentage (0-100)
    current_scanner = db.Column(db.String(50))  # Current active scanner
    metrics = db.Column(db.JSON)  # JSON string of scan metrics
    
    # Relationship to scan results
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert scan to dictionary format"""
        d = {
            'id': self.id,
            'url': self.url,
            'user_id': self.user_id,
            'status': self.status,
            'progress': self.progress,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'error_message': self.error_message,
            'current_scanner': self.current_scanner,
            'metrics': self.metrics,
            'results': [result.to_dict() for result in self.results]
        }
        return d
    
    def update_metrics(self, metrics_dict):
        """Update metrics as JSON string"""
        self.metrics = metrics_dict

class ScanResult(db.Model):
    """Model for storing individual vulnerability findings"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    vulnerability_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text)  # JSON string of evidence data
    timestamp = db.Column(db.DateTime(timezone=True), default=dt.now(timezone.utc))
    location = db.Column(db.String(500))  # URL or specific location where vulnerability was found
    created_at = db.Column(db.DateTime, default=dt.utcnow)
    status = db.Column(db.String(20), default='open')  # open, fixed, false_positive
    
    def to_dict(self):
        """Convert scan result to dictionary format"""
        d = {
            'id': self.id,
            'scan_id': self.scan_id,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'evidence': self.evidence
        }
        return d

    def update_evidence(self, evidence_dict):
        """Update evidence as JSON string"""
        self.evidence = json.dumps(evidence_dict)