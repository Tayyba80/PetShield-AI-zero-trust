from extension import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')

    def __repr__(self):
        return f'<User {self.email}>'
    

class UploadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    uploaded_by = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_data = db.Column(db.LargeBinary, nullable=False)

    def __repr__(self):
        return f'<UploadLog {self.filename}>'
    
#store every HTTP request (used to detect any multiple loggin fails or attack)
class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(200))      # e.g., "/upload"
    method = db.Column(db.String(10))        # GET/POST
    ip_address = db.Column(db.String(45))    # IPv4/IPv6
    user_agent = db.Column(db.String(300))   # Browser/device
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status_code = db.Column(db.Integer)      # HTTP status
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

#Used for admin dashboards and forensics (stores are the failed login/uploads/unauthorized access)
class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50))    # e.g., "failed_login"
    details = db.Column(db.String(500))      # Additional context
    ip_address = db.Column(db.String(45))
    user_email = db.Column(db.String(120), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# store all the anomalies and use them to train itself
class AnomalyDetectionModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))  # e.g., "login_anomaly"
    model_data = db.Column(db.LargeBinary)  # Serialized ML model
    last_trained = db.Column(db.DateTime)

# store all the ip blocked due to suspecious activities
class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True)
    reason = db.Column(db.String(200))  # "Too many failed logins"
    blocked_until = db.Column(db.DateTime)

