from flask import Flask, request, jsonify, send_from_directory, send_file
from users import UserManager
import os
import json
import subprocess
import base64
from collections import defaultdict
import time
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__, static_folder='frontend')

# Load config file
with open('config.json') as confFile:
    config = json.load(confFile)

# Ensure all API routes are registered before static routes
app.url_map.strict_slashes = False

# Configure CORS and other headers
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Initialize rate limiter and user manager
class RateLimiter:
    def __init__(self, max_requests=30, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)
    
    def is_allowed(self, ip):
        now = time.time()
        self.requests[ip] = [req_time for req_time in self.requests[ip] 
                           if now - req_time <= self.time_window]
        if len(self.requests[ip]) >= self.max_requests:
            return False
        self.requests[ip].append(now)
        return True

rate_limiter = RateLimiter()
user_manager = UserManager()

def get_client_ip():
    if 'X-Forwarded-For' in request.headers:
        # Get the original client IP if multiple are present
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

@app.before_request
def check_rate_limit():
    if not rate_limiter.is_allowed(get_client_ip()):
        return jsonify({'error': 'Too many requests'}), 429

# Special route for config.json
@app.route('/config.json')
def serve_config():
    return send_file('config.json', mimetype='application/json')

# Catch-all route for static files should be last
@app.route('/')
def serve_index():
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    try:
        # Add explicit MIME type mapping for SVG files
        if path.endswith('.svg'):
            return send_from_directory('frontend', path, mimetype='image/svg+xml')
        return send_from_directory('frontend', path)
    except:
        # If the file doesn't exist in frontend/, check the root directory
        if os.path.exists(path):
            # Also handle SVG files in root directory
            if path.endswith('.svg'):
                return send_file(path, mimetype='image/svg+xml')
            return send_file(path)
        return jsonify({'error': 'Not found'}), 404

def validate_session():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    return user_manager.validate_session(token)

def validate_admin():
    username = validate_session()
    if not username:
        return False
    return user_manager.is_admin(username)

def validate_user_admin():
    """Check if user can manage users"""
    username = validate_session()
    if not username:
        return False
    return user_manager.is_user_admin(username)

def validate_vdi_admin():
    """Check if user can manage VDI configurations"""
    username = validate_session()
    if not username:
        return False
    return user_manager.is_vdi_admin(username)

def validate_global_admin():
    """Check if user is a global admin"""
    username = validate_session()
    if not username:
        return False
    return user_manager.is_global_admin(username)

@app.route('/api/login', methods=['POST'])
def handle_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        totp_code = data.get('totp_code')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
            
        print(f"Login attempt for user: {username}")
        print(f"TOTP code provided: {totp_code is not None}")
        
        session_token = user_manager.authenticate(username, password, totp_code)
        print(f"Authentication result: {session_token}")
        
        if session_token == 'ACCOUNT_LOCKED':
            return jsonify({'error': 'This account has been locked. Please contact an administrator.'}), 401
        elif session_token == 'NEEDS_2FA_SETUP':
            secret, provisioning_uri, qr_code = user_manager.setup_2fa(username)
            return jsonify({
                'status': 'needs_2fa_setup',
                'username': username,
                'secret': secret,
                'provisioning_uri': provisioning_uri,
                'qr_code': qr_code
            })
        elif session_token == 'NEEDS_2FA':
            return jsonify({
                'status': 'needs_2fa',
                'username': username
            })
        elif session_token:
            return jsonify({
                'token': session_token,
                'username': username
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def handle_logout():
    username = validate_session()
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401
        
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    
    if user_manager.logout(token):
        return jsonify({'message': 'Logged out successfully'})
    return jsonify({'error': 'Invalid session'}), 401

@app.route('/api/session', methods=['GET'])
def handle_session():
    username = validate_session()
    if username:
        return jsonify({
            'authenticated': True,
            'username': username
        })
    return jsonify({'authenticated': False})

@app.route('/api/user-info', methods=['GET'])
def handle_user_info():
    username = validate_session()
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401
        
    is_admin = user_manager.is_admin(username)
    admin_level = user_manager.get_admin_level(username)
    return jsonify({
        'username': username,
        'is_admin': is_admin,
        'admin_level': admin_level
    })

@app.route('/api/change-password', methods=['POST'])
def handle_change_password():
    username = validate_session()
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Verify current password
        if not user_manager.verify_password_for_user(username, current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Change password
        if user_manager.change_password(username, new_password):
            return jsonify({'message': 'Password changed successfully'})
        else:
            return jsonify({'error': 'Failed to change password'}), 500
    except Exception as e:
        return jsonify({'error': f'Error changing password: {str(e)}'}), 500

@app.route('/api/vds-profiles', methods=['GET'])
def handle_vds_profiles():
    if not validate_session():
        return jsonify({'error': 'Not authenticated'}), 401

    profiles = []
    vds_profiles_dir = 'vdsProfiles'
    
    try:
        if not os.path.exists(vds_profiles_dir):
            return jsonify({'error': 'VDS profiles directory not found'}), 404

        for filename in os.listdir(vds_profiles_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(vds_profiles_dir, filename)) as f:
                        profile = json.load(f)
                        profiles.append({
                            'filename': filename,
                            **profile['vdsProperties']
                        })
                except json.JSONDecodeError as je:
                    print(f"Error parsing {filename}: {str(je)}")
                    continue
                except Exception as e:
                    print(f"Error loading {filename}: {str(e)}")
                    continue

        if not profiles:
            return jsonify({'error': 'No valid VDS profiles found'}), 404
            
        return jsonify({'profiles': profiles})
    except Exception as e:
        print(f"Error in handle_vds_profiles: {str(e)}")
        return jsonify({'error': f'Failed to load VDS profiles: {str(e)}'}), 500

@app.route('/api/launch', methods=['POST'])
def handle_launch():
    try:
        username = validate_session()
        if not username:
            return jsonify({'error': 'Not authenticated'}), 401

        data = request.get_json()
        vdiFile = data.get('vdiFile')
        if not vdiFile:
            return jsonify({'error': 'Missing required field: vdiFile'}), 400
        
        # Load the VDS profile
        try:
            with open(os.path.join('vdsProfiles', vdiFile)) as f:
                vds_profile = json.load(f)
                vdiUUID = vds_profile['vdsProperties']['uuid']
                expectedCIDR = vds_profile['vdsProperties']['expected_cidr_range']
        except Exception as e:
            return jsonify({'error': f'Failed to load VDS profile: {str(e)}'}), 400
            
        # Dev mode - skip Broker execution
        if os.getenv('SKIP_BROKER') == '1':
            return jsonify({'status': 'dev-skip', 'username': username, 'vdiFile': vdiFile})

        # Get VDS password from database
        vds_password = user_manager.get_vds_password(username)
        if not vds_password:
            return jsonify({'error': 'Failed to retrieve VDS password'}), 500

        # Execute Broker.py
        try:
            cmd = ['python3', 'Broker.py', username, vds_password, vdiFile, vdiUUID, expectedCIDR]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
            print(f"Broker output: {proc.stdout}")
            print(f"Broker error: {proc.stderr}")
            
            if proc.returncode != 0:
                error_msg = proc.stdout.strip() or proc.stderr.strip() or "Unknown error occurred"
                return jsonify({'error': error_msg}), 500
                
        except Exception as e:
            return jsonify({'error': f'Failed to execute broker: {str(e)}'}), 500

        # Parse JSON response from stdout
        try:
            for line in proc.stdout.splitlines():
                if line.startswith('{') and line.endswith('}'):
                    broker_response = json.loads(line)
                    break
            else:
                return jsonify({'error': 'No valid response from broker'}), 500
        except Exception as e:
            return jsonify({'error': 'Invalid response from broker'}), 500

        if 'connection_id' not in broker_response:
            return jsonify({'error': 'No connection ID in broker response'}), 500

        # Create base64-encoded connection string for Guacamole
        string_with_nulls = f"{broker_response['connection_id']}\x00c\x00postgresql"
        bytes_to_encode = string_with_nulls.encode('utf-8')
        broker_response['connection_string'] = base64.b64encode(bytes_to_encode).decode('utf-8')

        return jsonify(broker_response)
    except Exception as e:
        return jsonify({'error': f'Launch failed: {str(e)}'}), 500

@app.route('/api/setup-2fa', methods=['POST'])
def handle_2fa_setup():
    try:
        data = request.get_json()
        username = data.get('username')
        if not username:
            return jsonify({'error': 'Username required'}), 400
        
        secret, provisioning_uri, qr_code = user_manager.setup_2fa(username)
        return jsonify({
            'secret': secret,
            'provisioning_uri': provisioning_uri,
            'qr_code': qr_code
        })
    except Exception as e:
        return jsonify({'error': f'2FA setup failed: {str(e)}'}), 500

@app.route('/api/verify-2fa', methods=['POST'])
def handle_2fa_verify():
    try:
        data = request.get_json()
        username = data.get('username')
        code = data.get('code')
        
        if not username or not code:
            return jsonify({'error': 'Username and code required'}), 400
        
        if user_manager.verify_2fa(username, code):
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Invalid verification code'}), 401
    except Exception as e:
        return jsonify({'error': f'2FA verification failed: {str(e)}'}), 500

@app.route('/api/enable-2fa', methods=['POST'])
def handle_2fa_enable():
    try:
        data = request.get_json()
        username = data.get('username')
        code = data.get('code')
        
        if not username or not code:
            return jsonify({'error': 'Username and code required'}), 400
        
        if user_manager.enable_2fa(username, code):
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Invalid verification code'}), 401
    except Exception as e:
        return jsonify({'error': f'2FA enable failed: {str(e)}'}), 500

@app.route('/api/users', methods=['POST'])
def handle_users():
    try:
        if not validate_user_admin():
            return jsonify({'error': 'Unauthorized: User admin access required'}), 403
            
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        admin_level = data.get('admin_level', 0)
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Validate admin_level
        if admin_level not in [0, 1, 2, 3]:
            return jsonify({'error': 'Invalid admin level'}), 400
            
        success, message = user_manager.add_user(username, password, admin_level)
        if success:
            return jsonify({'message': message})
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        return jsonify({'error': f'Failed to create user: {str(e)}'}), 500

@app.route('/api/users/<username>/admin-level', methods=['PUT'])
def handle_set_admin_level(username):
    try:
        if not validate_user_admin():
            return jsonify({'error': 'Unauthorized: User admin access required'}), 403
        
        # Users can't modify their own admin level
        current_user = validate_session()
        if current_user == username and not validate_global_admin():
            return jsonify({'error': 'Cannot modify your own admin level'}), 403
            
        data = request.get_json()
        admin_level = data.get('admin_level')
        
        if admin_level is None:
            return jsonify({'error': 'admin_level required'}), 400
        
        # Validate admin_level
        if admin_level not in [0, 1, 2, 3]:
            return jsonify({'error': 'Invalid admin level (must be 0-3)'}), 400
            
        success, message = user_manager.set_admin_level(username, admin_level)
        if success:
            return jsonify({'message': message})
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        return jsonify({'error': f'Failed to update admin level: {str(e)}'}), 500

@app.route('/api/users/<username>', methods=['DELETE'])
def handle_delete_user(username):
    try:
        if not validate_user_admin():
            return jsonify({'error': 'Unauthorized: User admin access required'}), 403
        
        # Users can't delete their own account
        current_user = validate_session()
        if current_user == username:
            return jsonify({'error': 'Cannot delete your own account'}), 403
            
        # Delete the user
        success = user_manager.delete_user(username)
        if success:
            return jsonify({'message': f'User {username} deleted successfully'})
        else:
            return jsonify({'error': 'User not found or could not be deleted'}), 404
            
    except Exception as e:
        return jsonify({'error': f'Failed to delete user: {str(e)}'}), 500

@app.route('/api/users/list', methods=['GET'])
def handle_list_users():
    try:
        if not validate_user_admin():
            return jsonify({'error': 'Unauthorized: User admin access required'}), 403
        
        with user_manager.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT username, admin_level, is_locked, created_at FROM users ORDER BY username')
            users = [dict(row) for row in cursor.fetchall()]
        
        # Convert admin_level to readable format
        for user in users:
            levels = {0: 'user', 1: 'user_admin', 2: 'vdi_admin', 3: 'global_admin'}
            user['admin_level_name'] = levels.get(user['admin_level'], 'unknown')
        
        return jsonify({'users': users})
    except Exception as e:
        return jsonify({'error': f'Failed to list users: {str(e)}'}), 500

@app.route('/api/active-vdis', methods=['GET'])
def handle_active_vdis():
    try:
        username = validate_session()
        if not username:
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Get Guacamole URL from config
        with open('config.json') as f:
            config = json.load(f)
        
        guac_url = config.get('guacURL', '')
        guac_admin_user = config.get('guacAdminUser', 'guacadmin')
        guac_admin_pass = config.get('guacAdminPass', 'guacadmin')
        
        if not guac_url:
            return jsonify({'error': 'Guacamole not configured'}), 500
        
        # Authenticate with Guacamole as admin
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        auth_response = requests.post(
            f"{guac_url}/api/tokens",
            data={"username": guac_admin_user, "password": guac_admin_pass},
            verify=False
        )
        
        if auth_response.status_code != 200:
            return jsonify({'error': 'Failed to authenticate with Guacamole'}), 500
        
        auth_token = auth_response.json().get('authToken')
        if not auth_token:
            return jsonify({'error': 'Failed to get Guacamole auth token'}), 500
        
        # Get user's connections from Guacamole
        connections_response = requests.get(
            f"{guac_url}/api/session/data/postgresql/users/{username}/permissions?token={auth_token}",
            verify=False
        )
        
        if connections_response.status_code != 200:
            # User might not exist in Guacamole, return empty list
            return jsonify({'connections': []})
        
        permissions = connections_response.json()
        connections = []
        
        # Extract connection IDs from permissions
        if 'connectionPermissions' in permissions:
            for conn_id, conn_perms in permissions['connectionPermissions'].items():
                # Get connection details
                conn_response = requests.get(
                    f"{guac_url}/api/session/data/postgresql/connections/{conn_id}?token={auth_token}",
                    verify=False
                )
                
                if conn_response.status_code == 200:
                    conn_data = conn_response.json()
                    connections.append({
                        'id': conn_id,
                        'name': conn_data.get('name', f'Connection {conn_id}'),
                        'protocol': conn_data.get('protocol', 'unknown'),
                        'parameters': conn_data.get('parameters', {})
                    })
        
        return jsonify({'connections': connections})
    
    except Exception as e:
        print(f"Error fetching active VDIs: {str(e)}")
        return jsonify({'error': f'Failed to fetch active VDIs: {str(e)}'}), 500

@app.route('/api/vdi-profiles', methods=['GET'])
def handle_list_vdi_profiles():
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        profiles = []
        vdi_dir = 'vdsProfiles'
        
        if os.path.exists(vdi_dir):
            for filename in os.listdir(vdi_dir):
                if filename.endswith('.json'):
                    file_path = os.path.join(vdi_dir, filename)
                    try:
                        with open(file_path, 'r') as f:
                            profile_data = json.load(f)
                        profiles.append({
                            'filename': filename,
                            'vdsProperties': profile_data.get('vdsProperties', {}),
                            'guacPayload': profile_data.get('guacPayload', {})
                        })
                    except (json.JSONDecodeError, IOError):
                        # Skip files that can't be read or parsed
                        pass
        
        return jsonify({'profiles': profiles})
    except Exception as e:
        return jsonify({'error': f'Failed to list VDI profiles: {str(e)}'}), 500

@app.route('/api/vdi-profiles/upload', methods=['POST'])
def handle_upload_vdi_profile():
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Ensure filename is safe and ends with .json
        import re
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '', file.filename)
        if not safe_filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        if not safe_filename.endswith('.json'):
            safe_filename += '.json'
        
        try:
            # Parse and validate JSON
            content = file.read().decode('utf-8')
            profile_data = json.loads(content)
            
            # Validate required fields
            if 'vdsProperties' not in profile_data or 'guacPayload' not in profile_data:
                return jsonify({'error': 'Invalid profile format: must contain vdsProperties and guacPayload'}), 400
            
        except (json.JSONDecodeError, UnicodeDecodeError):
            return jsonify({'error': 'Invalid JSON file'}), 400
        
        # Ensure vdsProfiles directory exists
        vdi_dir = 'vdsProfiles'
        if not os.path.exists(vdi_dir):
            os.makedirs(vdi_dir)
        
        profile_path = os.path.join(vdi_dir, safe_filename)
        
        # Check if profile already exists
        if os.path.exists(profile_path):
            return jsonify({'error': f'VDI profile {safe_filename} already exists'}), 409
        
        # Write profile to disk
        with open(profile_path, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        return jsonify({'message': f'VDI profile {safe_filename} uploaded successfully', 'filename': safe_filename})
    except Exception as e:
        return jsonify({'error': f'Failed to upload VDI profile: {str(e)}'}), 500

@app.route('/api/vdi-profiles', methods=['POST'])
def handle_create_vdi_profile():
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        data = request.get_json()
        profile_name = data.get('filename')
        vds_properties = data.get('vdsProperties')
        guac_payload = data.get('guacPayload')
        
        if not profile_name or not vds_properties or not guac_payload:
            return jsonify({'error': 'Missing required fields: filename, vdsProperties, guacPayload'}), 400
        
        # Ensure filename ends with .json
        if not profile_name.endswith('.json'):
            profile_name += '.json'
        
        profile_path = os.path.join('vdsProfiles', profile_name)
        
        # Check if profile already exists
        if os.path.exists(profile_path):
            return jsonify({'error': 'VDI profile already exists'}), 409
        
        profile_data = {
            'vdsProperties': vds_properties,
            'guacPayload': guac_payload
        }
        
        with open(profile_path, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        return jsonify({'message': f'VDI profile {profile_name} created successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to create VDI profile: {str(e)}'}), 500

@app.route('/api/vdi-profiles/<filename>', methods=['PUT'])
def handle_update_vdi_profile(filename):
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        data = request.get_json()
        vds_properties = data.get('vdsProperties')
        guac_payload = data.get('guacPayload')
        
        if not vds_properties or not guac_payload:
            return jsonify({'error': 'Missing required fields: vdsProperties, guacPayload'}), 400
        
        profile_path = os.path.join('vdsProfiles', filename)
        
        # Check if profile exists
        if not os.path.exists(profile_path):
            return jsonify({'error': 'VDI profile not found'}), 404
        
        profile_data = {
            'vdsProperties': vds_properties,
            'guacPayload': guac_payload
        }
        
        with open(profile_path, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        return jsonify({'message': f'VDI profile {filename} updated successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to update VDI profile: {str(e)}'}), 500

@app.route('/api/vdi-profiles/<filename>', methods=['DELETE'])
def handle_delete_vdi_profile(filename):
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        profile_path = os.path.join('vdsProfiles', filename)
        
        # Check if profile exists
        if not os.path.exists(profile_path):
            return jsonify({'error': 'VDI profile not found'}), 404
        
        os.remove(profile_path)
        
        return jsonify({'message': f'VDI profile {filename} deleted successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to delete VDI profile: {str(e)}'}), 500

@app.route('/api/vdi-profiles/download/<filename>', methods=['GET'])
def download_vdi_profile(filename):
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        # Prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({'error': 'Invalid filename'}), 400
        
        profile_path = os.path.join('vdsProfiles', filename)
        
        # Check if profile exists
        if not os.path.exists(profile_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Send file for download
        return send_file(profile_path, as_attachment=True, download_name=filename, mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to download VDI profile: {str(e)}'}), 500

@app.route('/api/vdi-profiles/<filename>', methods=['GET'])
def handle_get_vdi_profile(filename):
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        # Prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({'error': 'Invalid filename'}), 400
        
        profile_path = os.path.join('vdsProfiles', filename)
        
        # Check if profile exists
        if not os.path.exists(profile_path):
            return jsonify({'error': 'VDI profile not found'}), 404
        
        # Read and return profile
        with open(profile_path, 'r') as f:
            profile_data = json.load(f)
        
        return jsonify(profile_data)
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve VDI profile: {str(e)}'}), 500

@app.route('/vdsProfiles/<filename>', methods=['GET'])
def serve_vdi_profile(filename):
    try:
        if not validate_vdi_admin():
            return jsonify({'error': 'Unauthorized: VDI admin access required'}), 403
        
        # Prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({'error': 'Invalid filename'}), 400
        
        profile_path = os.path.join('vdsProfiles', filename)
        
        # Check if profile exists
        if not os.path.exists(profile_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Send file for download
        return send_file(profile_path, as_attachment=True, download_name=filename, mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to download VDI profile: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8000)), debug=False)