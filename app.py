from flask import Flask, render_template, request, redirect, send_file, session, flash, url_for, jsonify
from flask_mail import Mail
from db import get_connection
import bcrypt
from datetime import datetime, date, timedelta
import re
import os
from werkzeug.utils import secure_filename
import requests as req
import json
import secrets
from google.auth.transport import requests
from google.oauth2 import id_token
import jwt
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import time
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ================= SECURITY CONFIGURATION =================

# Load configuration from environment variables with defaults
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Google OAuth Configuration - Load from environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')

try:
    mail = Mail(app)
except:
    print("Mail not configured. Running without email support.")

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ================= CONFIGURE LOGGING =================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# File handler for logs
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

# ================= SECURITY MIDDLEWARE =================

@app.before_request
def before_request():
    """Security headers and request validation"""
    # Rate limiting for sensitive endpoints
    sensitive_paths = ['/login', '/register', '/google-auth', '/google-register']
    if any(request.path.startswith(path) for path in sensitive_paths):
        # Check for suspicious patterns
        if len(request.get_data()) > 10000:  # 10KB max for auth requests
            logger.warning(f"Large request body detected from {request.remote_addr}")
            return jsonify({"error": "Request too large"}), 413

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # CSP header - adjust based on your needs
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://accounts.google.com https://*.google.com 'unsafe-inline'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://accounts.google.com;"
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response

# ================= SECURITY UTILITIES =================

def generate_csrf_token():
    """Generate CSRF token"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def validate_input(data, max_length=255):
    """Sanitize and validate input data"""
    if isinstance(data, str):
        # Remove potentially dangerous characters
        data = re.sub(r'[<>"\'\`]', '', data)
        # Limit length
        if len(data) > max_length:
            data = data[:max_length]
        # Trim whitespace
        data = data.strip()
    return data

def hash_password(password):
    """Hash password with bcrypt and pepper"""
    pepper = os.environ.get('PASSWORD_PEPPER', '').encode()
    # Combine password with pepper before hashing
    peppered_password = password.encode() + pepper
    return bcrypt.hashpw(peppered_password, bcrypt.gensalt(rounds=12))

def verify_password(password, hashed_password):
    """Verify password with bcrypt and pepper"""
    pepper = os.environ.get('PASSWORD_PEPPER', '').encode()
    peppered_password = password.encode() + pepper
    return bcrypt.checkpw(peppered_password, hashed_password)

def rate_limit_key():
    """Custom rate limiting key based on user and IP"""
    if 'user_id' in session:
        return f"{session['user_id']}:{get_remote_address()}"
    return get_remote_address()

def check_brute_force(user_id, ip_address):
    """Check for brute force attempts"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Count failed attempts in last 15 minutes
        cursor.execute("""
            SELECT COUNT(*) FROM login_attempts 
            WHERE user_id = %s AND ip_address = %s 
            AND attempt_time > NOW() - INTERVAL 15 MINUTE 
            AND success = 0
        """, (user_id, ip_address))
        
        failed_attempts = cursor.fetchone()[0] or 0
        
        # If more than 5 failed attempts in 15 minutes, block for 15 minutes
        if failed_attempts >= 5:
            logger.warning(f"Brute force detected for user {user_id} from IP {ip_address}")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Error checking brute force: {e}")
        return True
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def log_login_attempt(user_id, ip_address, success, user_agent=None):
    """Log login attempts for security monitoring"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                INDEX idx_user_ip (user_id, ip_address),
                INDEX idx_time (attempt_time)
            )
        """)
        
        cursor.execute("""
            INSERT INTO login_attempts (user_id, ip_address, user_agent, success)
            VALUES (%s, %s, %s, %s)
        """, (user_id, ip_address, user_agent, success))
        
        conn.commit()
    except Exception as e:
        logger.error(f"Error logging login attempt: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ================= DATABASE SCHEMA UPGRADES =================

def create_security_tables():
    """Create security-related tables if they don't exist"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Create login attempts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                INDEX idx_user_ip (user_id, ip_address),
                INDEX idx_time (attempt_time)
            )
        """)
        
        conn.commit()
        logger.info("Security tables created/updated successfully")
        
    except Exception as e:
        logger.error(f"Error creating security tables: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ================= AUTHENTICATION DECORATORS =================

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    @limiter.limit("100 per hour")
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path} from {request.remote_addr}")
            flash('Please login first', 'error')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect('/login')
        
        if session.get('user_type') != 'admin':
            logger.warning(f"Admin access denied for user {session['user_id']} to {request.path}")
            flash('Admin privileges required', 'error')
            return redirect('/dashboard')
        return f(*args, **kwargs)
    return decorated_function

# ================= UPLOAD CONFIGURATION =================

app.config['UPLOAD_FOLDER'] = 'static/uploads/assignments'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png', 'zip'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    # Validate filename
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Check extension
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    # Remove any path components
    filename = secure_filename(filename)
    # Add timestamp to make it unique
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
    return timestamp + filename

# ================= INITIALIZATION =================

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Create security tables on startup
create_security_tables()

# ================= GOOGLE OAUTH FUNCTIONS =================

def verify_google_token(token):
    """Verify Google ID token with enhanced security"""
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Check if token is from the correct audience
        if idinfo['aud'] != GOOGLE_CLIENT_ID:
            logger.warning(f"Invalid token audience: {idinfo['aud']}")
            return None
        
        # Check if token has expired
        if idinfo['exp'] < time.time():
            logger.warning("Google token has expired")
            return None
        
        # Verify issuer
        if idinfo.get('iss') not in ['accounts.google.com', 'https://accounts.google.com']:
            logger.warning(f"Invalid token issuer: {idinfo.get('iss')}")
            return None
        
        # Return user info
        return {
            'google_id': idinfo['sub'],
            'email': idinfo['email'],
            'name': validate_input(idinfo.get('name', '')),
            'picture': idinfo.get('picture', '')
        }
    except ValueError as e:
        logger.error(f"Google token verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Error verifying Google token: {e}")
        return None

def handle_google_user(google_user_info):
    """Handle Google user - check if exists, create if not"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        email = google_user_info['email']
        google_id = google_user_info['google_id']
        
        # Check if user exists with this Google ID
        cursor.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            # User exists with this Google ID, update last login
            cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (existing_user['id'],))
            conn.commit()
            return {
                'success': True,
                'user': existing_user,
                'is_new_user': False
            }
        
        # Check if user exists with this email (but different Google ID)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        email_user = cursor.fetchone()
        
        if email_user:
            # User exists with this email, link Google account
            cursor.execute("UPDATE users SET google_id = %s, last_login = NOW() WHERE id = %s", 
                          (google_id, email_user['id']))
            conn.commit()
            # Get updated user info
            cursor.execute("SELECT * FROM users WHERE id = %s", (email_user['id'],))
            updated_user = cursor.fetchone()
            return {
                'success': True,
                'user': updated_user,
                'is_new_user': False
            }
        
        # For Google login, user MUST exist first
        return {
            'success': False,
            'error': 'No account found with this email. Please register first.'
        }
        
    except Exception as e:
        logger.error(f"Error handling Google user: {e}")
        return {'success': False, 'error': str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def create_user_with_google(google_user_info):
    """Create a new user with Google authentication"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        email = google_user_info['email']
        google_id = google_user_info['google_id']
        name = google_user_info.get('name', '')
        
        # Generate username from email
        base_username = email.split('@')[0]
        username = base_username
        
        # Check if username exists
        counter = 1
        while True:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                username = f"{base_username}{counter}"
                counter += 1
            else:
                break
        
        # Generate random password for Google users
        random_password = bcrypt.hashpw(os.urandom(16), bcrypt.gensalt())
        
        # Insert new user
        cursor.execute("""
            INSERT INTO users (username, email, password, full_name, google_id, user_type, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            username,
            email,
            random_password,
            name,
            google_id,
            'student',  # Default user type
            'active'
        ))
        
        user_id = cursor.lastrowid
        conn.commit()
        
        # Get the new user
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        new_user = cursor.fetchone()
        
        return {
            'success': True,
            'user': new_user,
            'is_new_user': True
        }
        
    except Exception as e:
        logger.error(f"Error creating user with Google: {e}")
        return {'success': False, 'error': str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ================= ADDITIONAL UTILITY FUNCTIONS =================

def get_file_size_format(size_in_bytes):
    """Convert file size to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} TB"

def generate_student_id(course, enrollment_year):
    """Generate a unique student ID"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Extract course code (first 3 letters)
        course_code = course[:3].upper()
        
        # Get count of students in the same course and year
        cursor.execute(
            "SELECT COUNT(*) FROM students WHERE course LIKE %s AND YEAR(created_at) = %s",
            (f'{course_code}%', enrollment_year)
        )
        count = cursor.fetchone()[0] or 0
        
        # Format: COURSE-YEAR-001
        student_id = f"{course_code}-{enrollment_year}-{count + 1:03d}"
        return student_id
        
    except Exception as e:
        # Fallback to simple format if error occurs
        return f"STU-{enrollment_year}-{int(datetime.now().timestamp() % 10000):04d}"
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def validate_phone_number(phone):
    """Validate Indian phone number format"""
    if not phone or phone.strip() == '':
        return True, None
    
    phone = phone.strip()
    
    # Remove all non-digit characters
    digits = re.sub(r'\D', '', phone)
    
    # Indian phone numbers should be 10 digits
    if len(digits) == 10:
        return True, f"+91 {digits}"
    elif len(digits) > 10:
        # Already has country code, just format
        if phone.startswith('+91'):
            return True, phone
        else:
            return True, f"+91 {digits[-10:]}"
    else:
        return False, "Phone number must be 10 digits"

def validate_birth_date(birth_date_str):
    """Validate birth date (minimum 16 years old)"""
    if not birth_date_str or birth_date_str.strip() == '':
        return True, None
    
    try:
        birth_date = datetime.strptime(birth_date_str.strip(), '%Y-%m-%d').date()
        today = date.today()
        
        # Calculate age
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        
        if age < 14:
            return False, "Student must be at least 14 years old"
        if age > 80:
            return False, "Please enter a valid birth date"
        return True, birth_date_str
    except ValueError:
        return False, "Invalid date format"

def get_max_birth_date():
    """Get maximum birth date (16 years ago)"""
    today = date.today()
    max_date = date(today.year - 16, today.month, today.day)
    return max_date

def get_enrollment_years():
    """Get list of enrollment years (from 2020 to current+1)"""
    current_year = datetime.now().year
    return list(range(2020, current_year + 2))

# ================= ROUTES =================

@app.route("/")
def home():
    return redirect("/login")

# ================= UPDATED REGISTER ROUTE =================

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", key_func=get_remote_address)
def register():
    if request.method == "POST":
        # Get and validate input
        username = validate_input(request.form.get("username", "").strip(), max_length=50)
        email = validate_input(request.form.get("email", "").strip(), max_length=100)
        password = request.form.get("password", "")
        full_name = validate_input(request.form.get("full_name", "").strip(), max_length=100)
        
        # Validate required fields
        if not all([username, email, password]):
            flash("Username, email, and password are required", "error")
            return redirect("/register")
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address', 'error')
            return redirect("/register")
        
        # Validate password strength
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return redirect("/register")
        
        if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            flash("Password must contain both letters and numbers", "error")
            return redirect("/register")
        
        # Hash password
        hashed_password = hash_password(password)

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Check if username or email already exists
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", 
                          (username, email))
            if cursor.fetchone():
                flash("Username or Email already exists", "error")
                return redirect("/register")
            
            # Insert new user
            query = """INSERT INTO users (username, email, password, full_name, user_type, status) 
                       VALUES (%s, %s, %s, %s, 'student', 'active')"""
            cursor.execute(query, (username, email, hashed_password, full_name))
            user_id = cursor.lastrowid
            
            # Set session
            session["user_id"] = user_id
            session["username"] = username
            session["email"] = email
            session["name"] = full_name or username
            session["user_type"] = 'student'
            
            conn.commit()
            
            logger.info(f"New user registered: {username} ({email})")
            flash("Registration successful! Welcome!", "success")
            return redirect("/dashboard")
            
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            flash(f"Registration failed: {str(e)}", "error")
            return redirect("/register")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("register.html")

# ================= UPDATED LOGIN ROUTE WITH SECURITY =================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", key_func=rate_limit_key)
def login():
    if request.method == "POST":
        # Get and validate input
        username = validate_input(request.form.get("username", "").strip())
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password are required", "error")
            return redirect("/login")
        
        # Check for brute force
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Query user
            query = """
                SELECT id, username, email, password, full_name, user_type, status, google_id 
                FROM users WHERE username = %s OR email = %s
            """
            cursor.execute(query, (username, username))
            user = cursor.fetchone()
            
            if not user:
                # Log failed attempt (user not found)
                log_login_attempt(None, ip_address, False, user_agent)
                time.sleep(1)  # Delay to slow down brute force
                flash("Invalid credentials", "error")
                return redirect("/login")
            
            # Check brute force for this user
            if not check_brute_force(user['id'], ip_address):
                flash("Too many failed attempts. Please try again later.", "error")
                return redirect("/login")
            
            # Check if account is active
            if user['status'] != 'active':
                log_login_attempt(user['id'], ip_address, False, user_agent)
                flash("Your account is inactive. Please contact administrator.", "error")
                return redirect("/login")
            
            # Verify password
            if verify_password(password, user['password'].encode() if isinstance(user['password'], str) else user['password']):
                # Update last login
                cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))
                conn.commit()
                
                # Set session
                session["user_id"] = user['id']
                session["username"] = user['username']
                session["email"] = user['email']
                session["name"] = user['full_name'] or user['username']
                session["user_type"] = user['user_type']
                session["_fresh"] = True
                session["ip_address"] = ip_address
                
                # Log successful attempt
                log_login_attempt(user['id'], ip_address, True, user_agent)
                
                flash("Login successful!", "success")
                return redirect("/dashboard")
            else:
                # Log failed attempt
                log_login_attempt(user['id'], ip_address, False, user_agent)
                time.sleep(1)  # Delay to slow down brute force
                flash("Invalid credentials", "error")
                return redirect("/login")
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect("/login")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    # GET request - show login page
    return render_template("login.html", google_client_id=GOOGLE_CLIENT_ID)

# ================= GOOGLE OAUTH ROUTES =================

@app.route("/google-auth", methods=["POST"])
def google_auth():
    """Handle Google OAuth authentication"""
    try:
        if request.is_json:
            data = request.get_json()
            token = data.get('credential')  # This is the ID token from Google
            
            if not token:
                return jsonify({"success": False, "message": "No token provided"}), 400
            
            # Verify Google token
            google_user_info = verify_google_token(token)
            
            if not google_user_info:
                return jsonify({"success": False, "message": "Invalid Google token"}), 400
            
            # Handle the Google user (link to existing account)
            result = handle_google_user(google_user_info)
            
            if result['success']:
                user = result['user']
                
                # Set session
                session["user_id"] = user['id']
                session["username"] = user['username']
                session["email"] = user['email']
                session["name"] = user['full_name'] or user['username']
                session["user_type"] = user['user_type']
                session["google_id"] = user['google_id']
                
                message = "Google login successful!"
                if result.get('is_new_user'):
                    message = "Welcome! Your Google account has been linked."
                
                return jsonify({
                    "success": True, 
                    "message": message,
                    "redirect": "/dashboard"
                }), 200
            else:
                # User doesn't exist, ask them to register first
                return jsonify({
                    "success": False, 
                    "message": result.get('error', 'No account found with this email. Please register first.'),
                    "requires_registration": True,
                    "email": google_user_info['email']
                }), 200
    
    except Exception as e:
        logger.error(f"Google auth error: {e}")
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/google-register", methods=["POST"])
def google_register():
    """Register a new user with Google authentication"""
    try:
        if request.is_json:
            data = request.get_json()
            token = data.get('credential')
            
            if not token:
                return jsonify({"success": False, "message": "No token provided"}), 400
            
            # Verify Google token
            google_user_info = verify_google_token(token)
            
            if not google_user_info:
                return jsonify({"success": False, "message": "Invalid Google token"}), 400
            
            # Create new user with Google
            result = create_user_with_google(google_user_info)
            
            if result['success']:
                user = result['user']
                
                # Set session
                session["user_id"] = user['id']
                session["username"] = user['username']
                session["email"] = user['email']
                session["name"] = user['full_name'] or user['username']
                session["user_type"] = user['user_type']
                session["google_id"] = user['google_id']
                
                message = "Registration with Google successful!"
                if result.get('is_new_user'):
                    message = "Welcome! Your account has been created with Google."
                
                return jsonify({
                    "success": True, 
                    "message": message,
                    "redirect": "/dashboard"
                }), 200
            else:
                return jsonify({"success": False, "message": result.get('error', 'Registration failed')}), 400
    
    except Exception as e:
        logger.error(f"Google register error: {e}")
        return jsonify({"success": False, "message": "Server error"}), 500

# ================= ADDITIONAL SECURITY ROUTES =================

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if not all([current_password, new_password, confirm_password]):
            flash("All fields are required", "error")
            return redirect("/change-password")
        
        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return redirect("/change-password")
        
        if len(new_password) < 8:
            flash("New password must be at least 8 characters long", "error")
            return redirect("/change-password")
        
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Get current password hash
            cursor.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
            user = cursor.fetchone()
            
            if not user:
                flash("User not found", "error")
                return redirect("/change-password")
            
            # Verify current password
            if not verify_password(current_password, user['password'].encode() if isinstance(user['password'], str) else user['password']):
                flash("Current password is incorrect", "error")
                return redirect("/change-password")
            
            # Hash new password
            new_hashed_password = hash_password(new_password)
            
            # Update password
            cursor.execute("""
                UPDATE users 
                SET password = %s, last_password_change = NOW() 
                WHERE id = %s
            """, (new_hashed_password, session['user_id']))
            
            conn.commit()
            
            # Clear session to force re-login
            session.clear()
            
            flash("Password changed successfully. Please login again.", "success")
            return redirect("/login")
            
        except Exception as e:
            logger.error(f"Password change error: {e}")
            flash("An error occurred", "error")
            return redirect("/change-password")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    return render_template("change_password.html", username=session.get("username"))

@app.route("/logout")
def logout():
    """Enhanced logout with session cleanup"""
    user_id = session.get('user_id')
    if user_id:
        logger.info(f"User {user_id} logged out")
    
    # Clear all session data
    session.clear()
    
    # Set response headers to prevent caching
    response = redirect("/login")
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    flash("Logged out successfully!", "success")
    return response

# ================= ERROR HANDLERS =================

@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded from {request.remote_addr}")
    return jsonify(error="Rate limit exceeded. Please try again later."), 429

# ================= DASHBOARD =================

@app.route("/dashboard")
@login_required
def dashboard():
    # Get current date for display
    current_date = datetime.now().strftime("%A, %B %d, %Y")
    
    # Get user info from session
    username = session.get("username", "")
    email = session.get("email", "")
    name = session.get("name", username)
    user_type = session.get("user_type", "")
    
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Total students
        cursor.execute("SELECT COUNT(*) FROM students")
        total_students = cursor.fetchone()[0] or 0

        # Active teachers
        cursor.execute("SELECT COUNT(*) FROM teachers WHERE status='active'")
        active_teachers = cursor.fetchone()[0] or 0

        # Total courses
        cursor.execute("SELECT COUNT(*) FROM courses")
        total_courses = cursor.fetchone()[0] or 0

        # Mock attendance for demo
        attendance_rate = 94

        # Get recent students (limit to 10)
        cursor.execute("""
            SELECT s.id, s.name, s.email, s.course, s.phone, 
                   s.address, s.enrollment_year, s.created_at, 
                   s.student_id, s.status
            FROM students s 
            ORDER BY s.created_at DESC 
            LIMIT 10
        """)
        recent_students = cursor.fetchall()

        # Get recent active teachers
        cursor.execute("""
            SELECT id, name, email, subject, phone, 
                   qualification, status, created_at
            FROM teachers 
            WHERE status='active'
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        recent_teachers = cursor.fetchall()

        # Get upcoming assignments (if assignments table exists)
        upcoming_assignments = []
        try:
            cursor.execute("""
                SELECT assignment_name, due_date, course_id 
                FROM assignments 
                WHERE due_date >= CURDATE() 
                AND status = 'active'
                ORDER BY due_date ASC 
                LIMIT 5
            """)
            upcoming_assignments = cursor.fetchall()
        except:
            pass  # Assignments table might not exist yet

        # Get active schedules count
        active_schedules = 0
        try:
            cursor.execute("SELECT COUNT(*) FROM schedules WHERE status='active'")
            active_schedules = cursor.fetchone()[0] or 0
        except:
            pass

        return render_template(
            "dashboard.html",
            username=username,
            user_email=email,
            user_name=name,
            user_type=user_type,
            current_date=current_date,
            total_students=total_students,
            active_teachers=active_teachers,
            total_courses=total_courses,
            active_schedules=active_schedules,
            attendance_rate=attendance_rate,
            recent_students=recent_students,
            recent_teachers=recent_teachers,
            upcoming_assignments=upcoming_assignments
        )
        
    except Exception as e:
        logger.error(f"Error in dashboard route: {str(e)}")
        flash("Error loading dashboard data", "error")
        return render_template(
            "dashboard.html",
            username=username,
            user_email=email,
            user_name=name,
            user_type=user_type,
            current_date=current_date,
            total_students=0,
            active_teachers=0,
            total_courses=0,
            active_schedules=0,
            attendance_rate=0,
            recent_students=[],
            recent_teachers=[],
            upcoming_assignments=[]
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ================= STUDENT MANAGEMENT =================

@app.route("/students")
@login_required
def students():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Fetch all students
        cursor.execute("SELECT * FROM students ORDER BY id DESC")
        students = cursor.fetchall()
        
        return render_template("students.html", 
                             students=students, 
                             username=session["username"])
                             
    except Exception as e:
        logger.error(f"ERROR loading students: {str(e)}")
        flash("Error loading students", "error")
        return render_template("students.html", 
                             students=[], 
                             username=session["username"])
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/add-student", methods=["GET", "POST"])
@login_required
def add_student():
    # Prepare template data for GET request
    template_data = {
        'username': session["username"],
        'form_data': None,
        'enrollment_years': get_enrollment_years(),
        'current_year': datetime.now().year,
        'max_date': get_max_birth_date().isoformat()
    }
        
    if request.method == "POST":
        # Get form data
        form_data = {
            'name': request.form.get("name", "").strip(),
            'email': request.form.get("email", "").strip(),
            'course': request.form.get("course", "").strip(),
            'phone': request.form.get("phone", "").strip(),
            'birth_date': request.form.get("birth_date", "").strip(),
            'enrollment_year': request.form.get("enrollment_year", "").strip(),
            'address': request.form.get("address", "").strip(),
            'guardian_name': request.form.get("guardian_name", "").strip()
        }
        
        # Add form data to template data for re-population
        template_data['form_data'] = form_data
        
        # Validate required fields
        required_fields = ['name', 'email', 'course', 'enrollment_year']
        for field in required_fields:
            if not form_data[field]:
                flash(f"{field.replace('_', ' ').title()} is required", 'error')
                return render_template("add_student.html", **template_data)
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, form_data['email']):
            flash('Please enter a valid email address', 'error')
            return render_template("add_student.html", **template_data)
        
        # Validate phone number
        phone_valid, phone_result = validate_phone_number(form_data['phone'])
        if not phone_valid:
            flash(phone_result, 'error')
            return render_template("add_student.html", **template_data)
        
        # Format phone number if valid
        if phone_result:
            form_data['phone'] = phone_result
        
        # Validate birth date
        birth_valid, birth_result = validate_birth_date(form_data['birth_date'])
        if not birth_valid:
            flash(birth_result, 'error')
            return render_template("add_student.html", **template_data)
        
        # Check if email already exists
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM students WHERE email = %s", (form_data['email'],))
            if cursor.fetchone():
                flash("Email already exists. Please use a different email.", "error")
                return render_template("add_student.html", **template_data)
            
            # Generate student ID
            student_id = generate_student_id(form_data['course'], form_data['enrollment_year'])
            
            # Insert student into database
            query = """INSERT INTO students 
                       (name, email, course, phone, birth_date, enrollment_year, 
                        address, guardian_name, student_id, status) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active')"""
            
            cursor.execute(query, (
                form_data['name'],
                form_data['email'],
                form_data['course'],
                form_data['phone'],
                form_data['birth_date'] if form_data['birth_date'] else None,
                form_data['enrollment_year'],
                form_data['address'],
                form_data['guardian_name'],
                student_id
            ))
            conn.commit()
            
            flash(f'Student {form_data["name"]} added successfully! Student ID: {student_id}', 'success')
            return redirect("/students")
            
        except Exception as e:
            logger.error(f"Error adding student: {str(e)}")
            flash(f"Error adding student: {str(e)}", "error")
            return render_template("add_student.html", **template_data)
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # GET request - render empty form
    return render_template("add_student.html", **template_data)

@app.route("/delete-student/<int:student_id>")
@login_required
def delete_student(student_id):
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM students WHERE id = %s", (student_id,))
        conn.commit()
        
        flash("Student deleted successfully!", "success")
        
    except Exception as e:
        logger.error(f"Error deleting student: {str(e)}")
        flash(f"Error deleting student: {str(e)}", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return redirect("/students")

# ================= TEACHER MANAGEMENT =================

@app.route("/teachers")
@login_required
def teachers():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM teachers ORDER BY id DESC")
        teachers = cursor.fetchall()
        
        return render_template("teachers.html", 
                             teachers=teachers, 
                             username=session["username"])
                             
    except Exception as e:
        logger.error(f"ERROR loading teachers: {str(e)}")
        flash(f"Error loading teachers: {str(e)}", "error")
        return render_template("teachers.html", 
                             teachers=[], 
                             username=session["username"])
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/add-teacher", methods=["GET", "POST"])
@login_required
def add_teacher():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        phone = request.form.get("phone", "").strip()
        qualification = request.form.get("qualification", "").strip()

        if not all([name, email, subject]):
            flash("Name, Email, and Subject are required", "error")
            return redirect("/add-teacher")
        
        # Validate email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address', 'error')
            return redirect("/add-teacher")

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Check if email already exists
            cursor.execute("SELECT id FROM teachers WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email already exists. Please use a different email.", "error")
                return redirect("/add-teacher")

            query = """INSERT INTO teachers (name, email, subject, phone, qualification, status) 
                       VALUES (%s, %s, %s, %s, %s, 'active')"""
            cursor.execute(query, (name, email, subject, phone, qualification))
            conn.commit()

            flash("Teacher added successfully!", "success")
            return redirect("/teachers")
            
        except Exception as e:
            logger.error(f"Error adding teacher: {str(e)}")
            flash(f"Error adding teacher: {str(e)}", "error")
            return redirect("/add-teacher")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("add_teacher.html", username=session["username"])

@app.route("/toggle-teacher/<int:teacher_id>")
@login_required
def toggle_teacher(teacher_id):
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Get current status
        cursor.execute("SELECT status, name FROM teachers WHERE id = %s", (teacher_id,))
        result = cursor.fetchone()
        
        if not result:
            flash("Teacher not found", "error")
            return redirect("/teachers")
        
        current_status = result[0]
        teacher_name = result[1]
        
        # Toggle status
        new_status = 'inactive' if current_status == 'active' else 'active'
        cursor.execute("UPDATE teachers SET status = %s WHERE id = %s", 
                      (new_status, teacher_id))
        conn.commit()
        
        flash(f"Teacher '{teacher_name}' status changed to {new_status}!", "success")
        
    except Exception as e:
        logger.error(f"Error updating teacher: {str(e)}")
        flash(f"Error updating teacher: {str(e)}", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return redirect("/teachers")

# ================= COURSE MANAGEMENT =================

@app.route("/courses")
@login_required
def courses():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM courses ORDER BY id DESC")
        courses = cursor.fetchall()
        
        return render_template("courses.html", 
                             courses=courses, 
                             username=session["username"])
                             
    except Exception as e:
        logger.error(f"ERROR loading courses: {str(e)}")
        flash(f"Error loading courses: {str(e)}", "error")
        return render_template("courses.html", 
                             courses=[], 
                             username=session["username"])
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/add-course", methods=["GET", "POST"])
@login_required
def add_course():
    if request.method == "POST":
        course_name = request.form.get("course_name", "").strip()
        course_code = request.form.get("course_code", "").strip()
        duration = request.form.get("duration", "").strip()
        fee = request.form.get("fee", "0").strip()

        if not all([course_name, course_code]):
            flash("Course Name and Code are required", "error")
            return redirect("/add-course")

        try:
            fee = float(fee)
        except ValueError:
            fee = 0.0

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Check if course code already exists
            cursor.execute("SELECT id FROM courses WHERE course_code = %s", (course_code,))
            if cursor.fetchone():
                flash("Course code already exists. Please use a different code.", "error")
                return redirect("/add-course")

            query = """INSERT INTO courses (course_name, course_code, duration, fee) 
                       VALUES (%s, %s, %s, %s)"""
            cursor.execute(query, (course_name, course_code, duration, fee))
            conn.commit()

            flash("Course added successfully!", "success")
            return redirect("/courses")
            
        except Exception as e:
            logger.error(f"Error adding course: {str(e)}")
            flash(f"Error adding course: {str(e)}", "error")
            return redirect("/add-course")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("add_course.html", username=session["username"])

@app.route("/delete-course/<int:course_id>")
@login_required
def delete_course(course_id):
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM courses WHERE id = %s", (course_id,))
        conn.commit()
        
        flash("Course deleted successfully!", "success")
        
    except Exception as e:
        logger.error(f"Error deleting course: {str(e)}")
        flash(f"Error deleting course: {str(e)}", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return redirect("/courses")

# ================= SCHEDULE MANAGEMENT =================

@app.route("/schedules")
@login_required
def schedules():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get all schedules with their type counts
        cursor.execute("""
            SELECT s.*, 
                   COUNT(DISTINCT sp.id) as period_count,
                   COUNT(DISTINCT sb.id) as block_count,
                   COUNT(DISTINCT sa.id) as assignment_count
            FROM schedules s
            LEFT JOIN schedule_periods sp ON s.id = sp.schedule_id
            LEFT JOIN schedule_blocks sb ON s.id = sb.schedule_id
            LEFT JOIN schedule_assignments sa ON s.id = sa.schedule_id
            GROUP BY s.id
            ORDER BY s.start_date DESC, s.id DESC
        """)
        schedules_list = cursor.fetchall()
        
        # Get active schedule count for stats
        cursor.execute("SELECT COUNT(*) as active_count FROM schedules WHERE status = 'active'")
        active_stats = cursor.fetchone()
        
        # Get all schedule types for filter
        cursor.execute("SELECT DISTINCT schedule_type FROM schedules")
        schedule_types = [row['schedule_type'] for row in cursor.fetchall()]
        
        return render_template("schedules.html", 
                             schedules=schedules_list,
                             username=session["username"],
                             active_count=active_stats['active_count'] if active_stats else 0,
                             schedule_types=schedule_types)
                             
    except Exception as e:
        logger.error(f"Error loading schedules: {str(e)}")
        flash("Error loading schedules", "error")
        return render_template("schedules.html", 
                             schedules=[],
                             username=session["username"],
                             active_count=0,
                             schedule_types=[])
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route("/add-schedule", methods=["GET", "POST"])
@login_required
def add_schedule():
    if request.method == "POST":
        schedule_name = request.form.get("schedule_name", "").strip()
        schedule_type = request.form.get("schedule_type", "").strip()
        academic_year = request.form.get("academic_year", "").strip()
        semester = request.form.get("semester", "").strip()
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()
        description = request.form.get("description", "").strip()
        
        if not all([schedule_name, schedule_type, academic_year, start_date, end_date]):
            flash("Schedule Name, Type, Academic Year, and Dates are required", "error")
            return redirect("/add-schedule")
        
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Insert main schedule
            query = """
                INSERT INTO schedules (schedule_name, schedule_type, academic_year, semester, 
                                      start_date, end_date, description, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (schedule_name, schedule_type, academic_year, semester,
                                 start_date, end_date, description, session["username"]))
            schedule_id = cursor.lastrowid
            
            # Add default periods based on schedule type
            if schedule_type == 'traditional':
                # Traditional: 8 periods per day, 45 minutes each
                periods = [
                    (1, '08:00:00', '08:45:00', 'Period 1'),
                    (2, '08:45:00', '09:30:00', 'Period 2'),
                    (3, '09:30:00', '10:15:00', 'Period 3'),
                    (4, '10:15:00', '11:00:00', 'Period 4'),
                    (5, '11:00:00', '11:45:00', 'Period 5'),
                    (6, '11:45:00', '12:30:00', 'Period 6'),
                    (7, '13:30:00', '14:15:00', 'Period 7'),
                    (8, '14:15:00', '15:00:00', 'Period 8')
                ]
                for period_num, start_time, end_time, period_name in periods:
                    cursor.execute("""
                        INSERT INTO schedule_periods (schedule_id, period_number, start_time, end_time, period_name)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (schedule_id, period_num, start_time, end_time, period_name))
                    
            elif schedule_type == 'block':
                # Block scheduling: 4 blocks per day, 90 minutes each
                blocks = [
                    ('A', 'monday', '08:00:00', '09:30:00', 90),
                    ('B', 'monday', '09:45:00', '11:15:00', 90),
                    ('C', 'monday', '11:30:00', '13:00:00', 90),
                    ('D', 'monday', '13:30:00', '15:00:00', 90),
                    ('A', 'wednesday', '08:00:00', '09:30:00', 90),
                    ('B', 'wednesday', '09:45:00', '11:15:00', 90),
                    ('C', 'wednesday', '11:30:00', '13:00:00', 90),
                    ('D', 'wednesday', '13:30:00', '15:00:00', 90)
                ]
                for block_name, day, start_time, end_time, duration in blocks:
                    cursor.execute("""
                        INSERT INTO schedule_blocks (schedule_id, block_name, block_type, day_of_week, 
                                                    start_time, end_time, duration_minutes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (schedule_id, f"{block_name} Block", block_name, day, start_time, end_time, duration))
            
            conn.commit()
            flash(f"Schedule '{schedule_name}' created successfully!", "success")
            return redirect(f"/schedule-details/{schedule_id}")
            
        except Exception as e:
            logger.error(f"Error adding schedule: {str(e)}")
            flash(f"Error creating schedule: {str(e)}", "error")
            return redirect("/add-schedule")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # GET request
    current_year = datetime.now().year
    next_year = current_year + 1
    academic_years = [f"{current_year}-{next_year}", f"{next_year}-{next_year+1}"]
    
    return render_template("add_schedule.html",
                         username=session["username"],
                         academic_years=academic_years,
                         current_date=datetime.now().strftime('%Y-%m-%d'))

# ================= ASSIGNMENT MANAGEMENT =================

@app.route("/assignments")
@login_required
def assignments():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # First, ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assignments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                assignment_name VARCHAR(200) NOT NULL,
                assignment_type ENUM('homework', 'project', 'quiz', 'exam', 'lab', 'other') NOT NULL,
                course_id INT,
                teacher_id INT,
                schedule_id INT,
                due_date DATE NOT NULL,
                max_score INT DEFAULT 100,
                description TEXT,
                file_path VARCHAR(500),
                file_name VARCHAR(200),
                file_size INT,
                file_type VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(100),
                status ENUM('active', 'inactive', 'archived') DEFAULT 'active'
            )
        """)
        conn.commit()
        
        # Simple query - just get assignments
        cursor.execute("SELECT * FROM assignments ORDER BY due_date ASC, created_at DESC")
        assignments_list = cursor.fetchall()
        
        # Get simple counts
        total_assignments = len(assignments_list)
        upcoming_count = 0
        for assignment in assignments_list:
            if assignment['due_date'] and assignment['status'] == 'active':
                # Simple date comparison
                from datetime import datetime
                due_date = assignment['due_date']
                if isinstance(due_date, str):
                    due_date = datetime.strptime(due_date, '%Y-%m-%d').date()
                if due_date >= datetime.now().date():
                    upcoming_count += 1
        
        # Get other data (optional, handle errors)
        courses = []
        teachers = []
        schedules = []
        
        try:
            cursor.execute("SELECT id, course_name, course_code FROM courses LIMIT 10")
            courses = cursor.fetchall()
        except:
            pass
            
        try:
            cursor.execute("SELECT id, name, subject FROM teachers LIMIT 10")
            teachers = cursor.fetchall()
        except:
            pass
            
        try:
            cursor.execute("SELECT id, schedule_name, academic_year FROM schedules LIMIT 10")
            schedules = cursor.fetchall()
        except:
            pass
        
        from datetime import datetime
        now = datetime.now()
        
        return render_template("assignments.html",
                             assignments=assignments_list,
                             username=session["username"],
                             total_assignments=total_assignments,
                             upcoming_assignments=upcoming_count,
                             courses=courses,
                             teachers=teachers,
                             schedules=schedules,
                             now=now)
                             
    except Exception as e:
        logger.error(f"ERROR: {str(e)}")
        flash(f"Error loading assignments: {str(e)}", "error")
        
        from datetime import datetime
        return render_template("assignments.html",
                             assignments=[],
                             username=session["username"],
                             total_assignments=0,
                             upcoming_assignments=0,
                             courses=[],
                             teachers=[],
                             schedules=[],
                             now=datetime.now())
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    # Production settings
    if os.environ.get('FLASK_ENV') == 'production':
        # Use production server
        from waitress import serve
        logger.info("Starting production server...")
        serve(app, host='0.0.0.0', port=5000)
    else:
        # Development server
        app.run(debug=True, host='0.0.0.0', port=5000)