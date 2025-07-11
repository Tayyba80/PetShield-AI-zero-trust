from flask import Flask, render_template, request, redirect, session, flash, url_for
import os
import smtplib
import ssl
import random
import hashlib
from werkzeug.utils import secure_filename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from model import predict_image
#loading db
from extension import db
from models.user_model import User
# load .env file into app.py
from dotenv import load_dotenv
load_dotenv()
from models.user_model import UploadLog
#convert image into binary
from io import BytesIO
import base64
from models.user_model import RequestLog
from models.user_model import SecurityLog
from datetime import datetime, timedelta
from models.user_model import AnomalyDetectionModel
from models.user_model import BlockedIP
from security.anomaly_detection import train_login_anomaly_model
from sqlalchemy import func, case
import pickle
#from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.secret_key = os.urandom(24)


#------------------------------Model training Scheduler-------------------
# scheduler = BackgroundScheduler()
# scheduler.add_job(func=train_login_anomaly_model, trigger="interval", hours=1)
# scheduler.start()

# # To ensure the scheduler shuts down properly when Flask exits
# import atexit
# atexit.register(lambda: scheduler.shutdown())
#-------------------------------------------------------------------------

# connecting db (after loading from extension.py write this to properly connect with the db)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#initializing db
db.init_app(app)


# Custom filter for base64 encoding To show thw image in view_upload_logs
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None:
        return ''
    return base64.b64encode(data).decode('utf-8')

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER   store all uploaded images into a static folder
# ----------------- Utility Functions ------------------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_otp(email, otp):
    sender_email = os.environ.get("SMTP_EMAIL")
    sender_password = os.environ.get("SMTP_PASSWORD")
    
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your OTP for Login"
    message["From"] = sender_email
    message["To"] = email

    html = f"<html><body><p>Your OTP is: <strong>{otp}</strong></p></body></html>"
    message.attach(MIMEText(html, "html"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())


def log_security_event(event_type, details, user_email=None):
    """Log security-related events (failed logins, etc.)"""
    event = SecurityLog(
        event_type=event_type,
        details=details,
        ip_address=request.remote_addr,
        user_email=user_email,
        timestamp=datetime.utcnow()
    )
    db.session.add(event)
    db.session.commit()

def check_anomaly(ip):
    """Check if an IP's failed login behavior in the past hour is suspicious"""
    # Fetch failed login count for this IP in the last hour from security_log
    # Adjust for 5 hours difference manually
    one_hour_ago = datetime.now() - timedelta(hours=6)

    result = db.session.query(
        func.count().label("failed_logins")
    ).filter(
        SecurityLog.ip_address == ip,
        SecurityLog.event_type == 'failed_login',
        SecurityLog.timestamp > one_hour_ago
    ).first()

    failed_logins = result.failed_logins or 0

    if failed_logins == 0:
        return False  # No data to classify

    # Load anomaly detection model
    model_record = AnomalyDetectionModel.query.filter_by(name="login_anomaly").first()
    if not model_record:
        return False

    clf = pickle.loads(model_record.model_data)

    # Predict anomaly
    prediction = clf.predict([[failed_logins]])
    return prediction[0] == -1  # -1 indicates anomaly

# ----------------- Creating admin for once ----------------
#run it only once and then comment it

# with app.app_context():
#     admin_email = "tayybahaider198@gmail.com"
#     existing_user = User.query.filter_by(email=admin_email).first()
#     if not existing_user:
#         admin = User(
#             name="Admin User",
#             email=admin_email,
#             password=hash_password("admin123"),  # or use plain if not hashing
#             role="admin"
#         )
#         db.session.add(admin)
#         db.session.commit()
#         print("✅ Admin user created successfully!")
#     else:
#         print("⚠️ Admin user already exists.")

# ----------------- Security Headers ------------------
#WARNING: DON'T USE THESE HEADERS IF YOU WANT TO DISPLAY IMAGES ON YOUR SITE OTHERWISE YOU ARE GONNA DEBUG AND CHANGE AND CHANGE AND CHANGE YOU CODE FOR HOURS AND STILL NOT GONNA FIGURE OUT WHY IMAGES ARE NOT DISPLAYING 
# @app.after_request
# def set_security_headers(response):
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     response.headers['X-Frame-Options'] = 'DENY'
#     response.headers['Content-Security-Policy'] = "default-src 'self'"
#     return response

#--------------------- LOG REQUESTS  ---------------------------------------------
#Runs before every request
@app.before_request
def log_request_info():
    if request.endpoint and request.endpoint != 'static':
        user = User.query.filter_by(email=session.get('email')).first()
        log = RequestLog(
            endpoint=request.endpoint,
            method=request.method,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            user_id=user.id if user else None,
            status_code=0  # Temporary placeholder
        )
        db.session.add(log)
        db.session.flush()  # Assign ID without commit
        request.request_log_id = log.id  # Store for later

@app.after_request
def log_response_info(response):
    if hasattr(request, 'request_log_id'):
        log = RequestLog.query.get(request.request_log_id)
        if log:
            log.status_code = response.status_code
            db.session.commit()
    return response
# ----------------- Routes ------------------

@app.route('/')
def index():
    return render_template('landing_page.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = 'user'

        # Check if the email already exists in the database
        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for('login'))

        # Hash the password before saving to the database
        hashed_password = hash_password(password)
        
        # Create a new user and add it to the database
        new_user = User(name=name, email=email, password=hashed_password,role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully. Please login now.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr

    # Step 1: Check if IP is already blocked
    if BlockedIP.query.filter(
        BlockedIP.ip_address == ip,
        BlockedIP.blocked_until > datetime.now()
    ).first():
        flash("IP temporarily blocked for suspicious activity", "danger")
        return redirect(url_for('login'))

    # Step 2: Run anomaly detection using model trained on `security_log`
    if check_anomaly(ip):
        # Block the IP for 1 hour
        db.session.add(BlockedIP(
            ip_address=ip,
            reason="Suspicious security behavior",
            blocked_until=datetime.now() + timedelta(hours=1)
        ))
        db.session.commit()

        # Log the event
        log_security_event("ip_blocked", f"Blocked {ip} due to anomaly detected in security logs.")
        
        flash("Suspicious activity detected. Try again later.", "danger")
        return redirect(url_for('login'))

    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()

        if user and user.password == hash_password(password):
            session['email'] = user.email
            session['otp'] = str(random.randint(100000, 999999))
            try:
                send_otp(email, session['otp'])
                flash("OTP sent to your email. Please check your inbox.", "info")
                return redirect(url_for('verify_otp'))
            except Exception as e:
                flash("Failed to send OTP. Check your email config.", "danger")
                print(e)
                return redirect(url_for('login'))
        else:
            log_security_event(
                "failed_login",
                f"Failed login attempt for {email} from {request.remote_addr}",
                user_email=email
            )

        flash("Invalid credentials. Try again.", "danger")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if entered_otp == session.get('otp'):
            session['authenticated'] = True

            # Get the user from the database using the stored email
            user = User.query.filter_by(email=session.get('email')).first()

            if user:
                session['role'] = user.role  # Save role in session

                flash("OTP verified successfully!", "success")

                # Redirect based on role
                if user.role == 'admin':
                    return redirect(url_for('admin_panel'))
                else:
                    return redirect(url_for('upload_file'))
            else:
                flash("User not found.", "danger")
                return redirect(url_for('login'))
        else:
            log_security_event(
            "invalid_otp",
            f"Failed OTP attempt for {session.get('email')} from {request.remote_addr}",
            user_email=session.get('email')
            )
            flash("Invalid OTP. Try again.", "danger")
            return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not session.get('authenticated'):
        flash("Unauthorized access. Please log in.", 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part!', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'warning')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Read the file as binary data
            file_data = file.read()

            # Store the file and its metadata in the database
            filename = secure_filename(file.filename)
            user_email = session['email']
            upload_log = UploadLog(
                filename=filename,
                uploaded_by=user_email,
                file_data=file_data
            )
            db.session.add(upload_log)
            db.session.commit()

            # Call prediction function if needed
            result = predict_image(file_data)

            flash(f"File {filename} uploaded successfully!", "success")
            return render_template('result.html', filename=filename, result=result)
        else:
            log_security_event(
            "invalid_file_attempt",
            f"User {session.get('email')} tried uploading {file.filename}",
            user_email=session.get('email')
            )
            flash('Invalid file type!', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

@app.route('/admin/view-upload-logs')
def view_upload_logs():
    if 'authenticated' not in session or not session.get('email'):
        flash("You need to login first.", "warning")
        return redirect(url_for('login'))

    current_user = User.query.filter_by(email=session['email']).first()

    if current_user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('upload_file'))

    upload_logs = UploadLog.query.all()
    return render_template('view_upload_logs.html', upload_logs=upload_logs)


@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if not session.get('authenticated'):
        log_security_event(
            "unauthorized_admin_access",
            f"Non-admin user {session.get('email')} attempted to access /admin/view-users",
            user_email=session.get('email')
        )
        flash("Unauthorized access. Please log in.", 'warning')
        return redirect(url_for('login'))
    return render_template('admin.html')

@app.route('/admin/view-users')
def view_users():
    if 'authenticated' not in session or not session.get('email'):
        flash("You need to login first.", "warning")
        return redirect(url_for('login'))

    # Fetch the logged-in user
    current_user = User.query.filter_by(email=session['email']).first()

    if current_user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('upload_file'))

    all_users = User.query.all()
    return render_template('view_users.html', users=all_users)

@app.route("/admin/blocked_ips")
def view_blocked_ips():
    if 'authenticated' not in session or not session.get('email'):
        flash("You need to login first.", "warning")
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(email=session['email']).first()
    if current_user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('upload_file'))
    
    blocked_ips = BlockedIP.query.order_by(BlockedIP.blocked_until.desc()).all()
    return render_template("blocked_ips.html", blocked_ips=blocked_ips)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    #with app.app_context():#run only once to create the db (last thing to do to complete db attatchment, this will creat instance folder which containd db. run it each time when add anything in db) 
        #db.create_all()  
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
