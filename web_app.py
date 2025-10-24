#!/usr/bin/env python3
from flask import Flask, request, render_template_string, send_from_directory, session, redirect, url_for, flash
import subprocess
import json
import os
from functools import wraps
from users import UserManager
from tls_config import configure_reverse_proxy_headers, ReverseProxyHeaders, TLSConfig
from shutdown_handler import initialize_shutdown_handler, register_cleanup
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management
user_manager = UserManager()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize graceful shutdown handler
shutdown_handler = initialize_shutdown_handler(app)
logger.info("Graceful shutdown handler initialized")

# Initialize TLS configuration
tls_config = TLSConfig()

# Configure reverse proxy header handling if enabled
if tls_config.reverse_proxy_enabled:
    configure_reverse_proxy_headers(app)
    logger.info("Reverse proxy header handling enabled")

# Middleware to prevent new requests during shutdown
@app.before_request
def check_shutdown_status():
    """Reject new requests if shutdown is in progress."""
    if os.getenv("XBROKER_SHUTTING_DOWN") == "1":
        logger.warning(f"Rejecting request during shutdown: {request.method} {request.path}")
        return {"error": "Server is shutting down"}, 503

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    
    # Determine if we're HTTPS
    is_https = ReverseProxyHeaders.is_https(request) if tls_config.reverse_proxy_enabled else request.is_secure
    
    # HSTS (HTTP Strict Transport Security)
    # Only set if we detected HTTPS
    if is_https:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # CSP (Content Security Policy)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:"
    
    # X-Frame-Options (Clickjacking protection)
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-Content-Type-Options (MIME type sniffing protection)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-XSS-Protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer-Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions-Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'
    
    return response

# Session configuration for secure cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Don't expose to JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['SESSION_COOKIE_NAME'] = '__Secure-xbroker_session'
app.config['SESSION_COOKIE_AGE'] = 3600  # 1 hour
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Load VDS profiles from directory
def load_vds_profiles():
    profiles = {}
    vds_profiles_dir = 'vdsProfiles'
    
    for filename in os.listdir(vds_profiles_dir):
        if filename.endswith('.json'):
            with open(os.path.join(vds_profiles_dir, filename)) as f:
                profile = json.load(f)
                profiles[filename] = profile['vdsProperties']
    
    return profiles

vdsConfFiles = load_vds_profiles()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'session_token' not in session:
            return redirect(url_for('login'))
        username = user_manager.validate_session(session['session_token'])
        if not username or not user_manager.is_admin(username):
            flash('Admin access required')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form.get('totp_code')
        
        session_token = user_manager.authenticate(username, password, totp_code)
        
        if session_token == 'ACCOUNT_LOCKED':
            flash('This account has been locked. Please contact an administrator.')
        elif session_token == 'NEEDS_2FA_SETUP':
            # Store credentials temporarily for 2FA setup
            session['2fa_setup_username'] = username
            session['2fa_setup_password'] = password
            return redirect(url_for('setup_2fa'))
        elif session_token == 'NEEDS_2FA':
            # Store credentials temporarily for 2FA verification
            session['2fa_pending_username'] = username
            session['2fa_pending_password'] = password
            return redirect(url_for('verify_2fa'))
        elif session_token:
            session['session_token'] = session_token
            return redirect(url_for('admin_panel' if user_manager.is_admin(username) else 'index'))
        else:
            flash('Invalid credentials')
    return render_template_string('''
        <h2>Login</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <p style="color: red;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
    ''')

@app.route('/logout')
def logout():
    if 'session_token' in session:
        user_manager.logout(session['session_token'])
        session.pop('session_token', None)
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_panel():
    with user_manager.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username, is_admin, created_at FROM users ORDER BY username')
        users = cursor.fetchall()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Management</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .add-user-form { margin: 20px 0; padding: 20px; background-color: #f9f9f9; }
            </style>
        </head>
        <body>
            <h2>User Management</h2>
            <div class="add-user-form">
                <h3>Add New User</h3>
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <p style="color: {% if 'success' in message %}green{% else %}red{% endif %};">
                                {{ message }}
                            </p>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <form method="post" action="{{ url_for('add_user') }}">
                    <p>Username: <input type="text" name="username" required></p>
                    <p>Password: <input type="password" name="password" required></p>
                    <p><input type="checkbox" name="is_admin" value="1"> Admin User</p>
                    <p><input type="submit" value="Add User"></p>
                </form>
            </div>
            
            <h3>Existing Users</h3>
            <table>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
                {% for user in users %}
                <tr>
                    <td>{{ user['username'] }}</td>
                    <td>{{ 'Admin' if user['is_admin'] else 'User' }}</td>
                    <td>{{ 'Locked' if user['is_locked'] else 'Active' }}</td>
                    <td>{{ user['created_at'] }}</td>
                    <td>
                        {% if user['username'] != session['username'] %}
                            <form method="post" action="{{ url_for('toggle_lock_user') }}" style="display: inline;">
                                <input type="hidden" name="username" value="{{ user['username'] }}">
                                <input type="hidden" name="lock" value="{{ '0' if user['is_locked'] else '1' }}">
                                <input type="submit" value="{{ 'Unlock' if user['is_locked'] else 'Lock' }}"
                                       onclick="return confirm('Are you sure you want to {{ 'unlock' if user['is_locked'] else 'lock' }} this account?')">
                            </form>
                            
                            <button onclick="showResetPassword('{{ user['username'] }}')" style="display: inline;">
                                Reset Password
                            </button>
                            
                            <form method="post" action="{{ url_for('delete_user') }}" style="display: inline;">
                                <input type="hidden" name="username" value="{{ user['username'] }}">
                                <input type="submit" value="Delete" 
                                       onclick="return confirm('Are you sure you want to delete this user?')">
                            </form>
                        {% else %}
                            <em>Current User</em>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
            
            <!-- Password Reset Dialog -->
            <div id="passwordResetDialog" style="display: none; position: fixed; top: 50%; left: 50%; 
                transform: translate(-50%, -50%); background: white; padding: 20px; border: 1px solid #ccc; 
                box-shadow: 0 0 10px rgba(0,0,0,0.5); z-index: 1000;">
                <h3>Reset Password</h3>
                <form method="post" action="{{ url_for('reset_user_password') }}">
                    <input type="hidden" name="username" id="resetUsername">
                    <p>New Password: <input type="password" name="new_password" required></p>
                    <p>Confirm Password: <input type="password" name="confirm_password" required></p>
                    <input type="submit" value="Reset Password">
                    <button type="button" onclick="hideResetPassword()">Cancel</button>
                </form>
            </div>
            
            <script>
                function showResetPassword(username) {
                    document.getElementById('resetUsername').value = username;
                    document.getElementById('passwordResetDialog').style.display = 'block';
                }
                
                function hideResetPassword() {
                    document.getElementById('passwordResetDialog').style.display = 'none';
                }
            </script>
            <p><a href="{{ url_for('logout') }}">Logout</a></p>
        </body>
        </html>
    ''', users=users)

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    is_admin = 'is_admin' in request.form
    
    success, message = user_manager.add_user(username, password, is_admin)
    flash('Success: User added!' if success else f'Error: {message}')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def delete_user():
    username = request.form['username']
    if username == session.get('username'):
        flash('Error: Cannot delete your own account')
        return redirect(url_for('admin_panel'))
    
    with user_manager.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
    
    flash('Success: User deleted!')
    return redirect(url_for('admin_panel'))

@app.route('/setup-2fa')
def setup_2fa():
    # Check for first-time setup
    username = session.get('2fa_setup_username')
    if not username:
        # Check for regular session
        if 'session_token' not in session:
            return redirect(url_for('login'))
        username = user_manager.validate_session(session['session_token'])
        if not username:
            return redirect(url_for('login'))
        
    if user_manager.is_2fa_enabled(username):
        flash('2FA is already enabled for your account')
        return redirect(url_for('index'))
        
    secret, qr_code = user_manager.setup_2fa(username)
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Set up Two-Factor Authentication</title>
            <style>
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .qr-code { text-align: center; margin: 20px 0; }
                .instructions { margin: 20px 0; }
                .setup-form { margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Set up Two-Factor Authentication</h2>
                
                <div class="instructions">
                    <p>1. Install an authenticator app on your phone (like Google Authenticator or Authy)</p>
                    <p>2. Scan this QR code with your authenticator app:</p>
                </div>
                
                <div class="qr-code">
                    <img src="{{ qr_code }}" alt="QR Code">
                </div>
                
                <div class="setup-form">
                    <p>3. Enter the 6-digit code from your authenticator app to verify:</p>
                    <form method="post" action="{{ url_for('enable_2fa') }}">
                        <input type="text" name="code" pattern="[0-9]{6}" required 
                               placeholder="Enter 6-digit code">
                        <input type="submit" value="Verify and Enable 2FA">
                    </form>
                </div>
                
                <p><strong>Important:</strong> Save your recovery code: {{ secret }}</p>
            </div>
        </body>
        </html>
    ''', qr_code=qr_code, secret=secret)

@app.route('/enable-2fa', methods=['POST'])
def enable_2fa():
    # Check for first-time setup
    username = session.get('2fa_setup_username')
    if not username:
        # Check for regular session
        if 'session_token' not in session:
            return redirect(url_for('login'))
        username = user_manager.validate_session(session['session_token'])
        if not username:
            return redirect(url_for('login'))
        
    code = request.form.get('code')
    if not code:
        flash('Please enter a verification code')
        return redirect(url_for('setup_2fa'))
        
    if user_manager.enable_2fa(username, code):
        flash('2FA has been enabled successfully!')
        
        # Handle first-time setup completion
        if 'session_token' not in session and session.get('2fa_setup_username'):
            # Complete the login process
            session_token = user_manager.authenticate(
                username,
                session.get('2fa_setup_password'),
                code
            )
            if session_token and session_token not in ['NEEDS_2FA', 'NEEDS_2FA_SETUP', 'ACCOUNT_LOCKED']:
                session['session_token'] = session_token
                # Clean up setup session data
                session.pop('2fa_setup_username', None)
                session.pop('2fa_setup_password', None)
                return redirect(url_for('admin_panel' if user_manager.is_admin(username) else 'index'))
        
        return redirect(url_for('index'))
    else:
        flash('Invalid verification code')
        return redirect(url_for('setup_2fa'))

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        username = session.get('2fa_pending_username')
        code = request.form.get('code')
        
        if not username or not code:
            return redirect(url_for('login'))
            
        # Re-authenticate with 2FA code
        session_token = user_manager.authenticate(
            username, 
            session.get('2fa_pending_password', ''),
            code
        )
        
        # Clean up temporary session data
        session.pop('2fa_pending_username', None)
        session.pop('2fa_pending_password', None)
        
        if session_token and session_token != 'NEEDS_2FA':
            session['session_token'] = session_token
            return redirect(url_for('admin_panel' if user_manager.is_admin(username) else 'index'))
            
        flash('Invalid verification code')
        
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verify 2FA</title>
            <style>
                .container { max-width: 400px; margin: 0 auto; padding: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Two-Factor Authentication</h2>
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <p style="color: red;">{{ message }}</p>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                <form method="post">
                    <p>Enter the 6-digit code from your authenticator app:</p>
                    <input type="text" name="code" pattern="[0-9]{6}" required 
                           placeholder="Enter 6-digit code">
                    <input type="submit" value="Verify">
                </form>
            </div>
        </body>
        </html>
    ''')

# Serve the static frontend folder

@app.route('/admin/toggle_lock_user', methods=['POST'])
@admin_required
def toggle_lock_user():
    username = request.form['username']
    lock = request.form['lock'] == '1'
    
    if username == session.get('username'):
        flash('Error: Cannot lock your own account')
        return redirect(url_for('admin_panel'))
    
    if user_manager.set_account_lock(username, lock):
        flash(f'Success: Account {"locked" if lock else "unlocked"}!')
    else:
        flash('Error: Failed to update account status')
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/reset_password', methods=['POST'])
@admin_required
def reset_user_password():
    username = request.form['username']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    if username == session.get('username'):
        flash('Error: Use profile settings to change your own password')
        return redirect(url_for('admin_panel'))
    
    if new_password != confirm_password:
        flash('Error: Passwords do not match')
        return redirect(url_for('admin_panel'))
    
    if len(new_password) < 8:
        flash('Error: Password must be at least 8 characters long')
        return redirect(url_for('admin_panel'))
    
    if user_manager.change_user_password(username, new_password, admin_action=True):
        flash('Success: Password has been reset!')
    else:
        flash('Error: Failed to reset password')
    
    return redirect(url_for('admin_panel'))

# Serve the static frontend folder
@app.route('/frontend/<path:filename>')
def frontend_static(filename):
    return send_from_directory('frontend', filename)

@app.route('/frontend/')
def frontend_index():
    return send_from_directory('frontend', 'index.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'session_token' not in session:
        return redirect(url_for('login'))
    
    username = user_manager.validate_session(session['session_token'])
    if not username:
        session.pop('session_token', None)
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            rUser = request.form['username']
            rPass = request.form['password']
            vdiFile = request.form['vdiFile']
            # Load profile for this VDI
            with open(os.path.join('vdsProfiles', vdiFile)) as f:
                profile = json.load(f)
                vdiUUID = profile['vdsProperties']['uuid']
                expectedCIDR = profile['vdsProperties']['expected_cidr_range']
            
            # Execute the Broker script with the provided username, password, VDI file, UUID, and expected CIDR range
            process = subprocess.run(
                ['python3', 'Broker.py', rUser, rPass, vdiFile, vdiUUID, expectedCIDR],
                text=True,
                capture_output=True,
                check=True
            )
            
            if process.returncode != 0:
                error_msg = process.stderr.strip() or "Unknown error occurred"
                app.logger.error(f"Broker script error: {error_msg}")
                return {'error': f"Broker script error: {error_msg}"}, 500
            
            app.logger.info(f"Broker output: {process.stdout}")
            return {'status': 'success', 'message': process.stdout}, 200
        except Exception as e:
            error_msg = str(e)
            app.logger.error(f"Error: {error_msg}")
            return {'error': error_msg}, 500
    
    return render_template_string('''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            Choose a VDI: <select name="vdiFile">
                {% for file, details in vdsConfFiles.items() %}
                    <option value="{{ file }}">{{ details['displayName'] }}</option>
                {% endfor %}
            </select><br>
            <input type="submit" value="Submit">
        </form>
    ''', vdsConfFiles=vdsConfFiles)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)