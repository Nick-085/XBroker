#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
import cgi
import subprocess
import requests
from urllib.parse import urlparse
import time
from collections import defaultdict
from users import UserManager

# Simple rate limiting
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

# Load config file
with open('config.json') as confFile:
    config = json.load(confFile)

PORT = int(os.getenv('PORT', 8000))
FRONTEND_DIR = 'frontend'

class Handler(http.server.SimpleHTTPRequestHandler):
    # Set maximum request size to 1MB to prevent DOS
    max_request_size = 1024 * 1024
    
    def __init__(self, *args, **kwargs):
        self.headers_sent = False
        super().__init__(*args, **kwargs)
        
    def log_message(self, format, *args):
        """Log messages with more detail"""
        print(f"[{self.log_date_time_string()}] {self.address_string()} - {format%args}")
        
    def log_error(self, format, *args):
        """Log errors with more detail"""
        print(f"ERROR [{self.log_date_time_string()}] {self.address_string()} - {format%args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/api/vds-profiles':
            if not self.validate_session():
                return self._json_response({'error': 'Not authenticated'}, 401)
            self.handle_vds_profiles()
        elif parsed.path == '/api/session':
            self.handle_session()
        elif parsed.path == '/api/user-info':
            if not self.validate_session():
                return self._json_response({'error': 'Not authenticated'}, 401)
            self.handle_user_info()
        else:
            try:
                return super().do_GET()
            except Exception as e:
                print(f"Error serving static file: {str(e)}")
                self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        
        # Get client IP, checking for proxy headers
        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0])
        if ',' in client_ip:  # Get the original client IP if multiple are present
            client_ip = client_ip.split(',')[0].strip()
            
        # Apply rate limiting
        if not rate_limiter.is_allowed(client_ip):
            self._json_response({'error': 'Too many requests'}, 429)
            return
            
        # Check request size
        content_length = int(self.headers.get('content-length', 0))
        if content_length > self.max_request_size:
            self._json_response({'error': 'Request too large'}, 413)
            return

        if parsed.path == '/api/login':
            self.handle_login()
        elif parsed.path == '/api/logout':
            if not self.validate_session():
                return self._json_response({'error': 'Not authenticated'}, 401)
            self.handle_logout()
        elif parsed.path == '/api/launch':
            if not self.validate_session():
                return self._json_response({'error': 'Not authenticated'}, 401)
            self.handle_launch()
        elif parsed.path == '/api/users':
            if not self.validate_session():
                return self._json_response({'error': 'Not authenticated'}, 401)
            self.handle_users()
        else:
            self.send_error(404, 'Not found')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()

    def validate_session(self):
        auth_token = self.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return False
        token = auth_token.split(' ')[1]
        return user_manager.validate_session(token) is not None
        
    def validate_admin(self):
        """Check if the current user is an admin"""
        auth_token = self.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return False
        token = auth_token.split(' ')[1]
        username = user_manager.validate_session(token)
        if not username:
            return False
        return user_manager.is_admin(username)

    def handle_session(self):
        auth_token = self.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return self._json_response({'authenticated': False})
            
        token = auth_token.split(' ')[1]
        username = user_manager.validate_session(token)
        
        if username:
            return self._json_response({
                'authenticated': True,
                'username': username
            })
        return self._json_response({'authenticated': False})

    def handle_user_info(self):
        auth_token = self.headers.get('Authorization').split(' ')[1]
        username = user_manager.validate_session(auth_token)
        is_admin = user_manager.is_admin(username)
        
        return self._json_response({
            'username': username,
            'is_admin': is_admin
        })

    def handle_login(self):
        try:
            content_length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return self._json_response({'error': 'Username and password required'}, 400)
                
            session_token = user_manager.authenticate(username, password)
            if session_token:
                return self._json_response({
                    'token': session_token,
                    'username': username
                })
            else:
                return self._json_response({'error': 'Invalid credentials'}, 401)
        except Exception as e:
            return self._json_response({'error': f'Login failed: {str(e)}'}, 500)

    def handle_logout(self):
        auth_token = self.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return self._json_response({'error': 'Not authenticated'}, 401)
            
        token = auth_token.split(' ')[1]
        if user_manager.logout(token):
            return self._json_response({'message': 'Logged out successfully'})
        return self._json_response({'error': 'Invalid session'}, 401)

    def handle_vds_profiles(self):
        print(f"Handling /api/vds-profiles request")
        profiles = []
        vds_profiles_dir = 'vdsProfiles'
        print(f"Looking for profiles in directory: {os.path.abspath(vds_profiles_dir)}")
        
        try:
            if not os.path.exists(vds_profiles_dir):
                return self._json_response({'error': f'VDS profiles directory not found'}, 404)

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
                return self._json_response({'error': 'No valid VDS profiles found'}, 404)
                
            return self._json_response({'profiles': profiles})
        except Exception as e:
            print(f"Error in handle_vds_profiles: {str(e)}")
            return self._json_response({'error': f'Failed to load VDS profiles: {str(e)}'}, 500)

    def handle_launch(self):
        try:
            length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(length).decode('utf-8')
            data = json.loads(body) if body else {}
        except Exception as e:
            return self._json_response({'error': f'Failed to parse request: {str(e)}'}, 400)

        auth_token = self.headers.get('Authorization')
        if not auth_token or not auth_token.startswith('Bearer '):
            return self._json_response({'error': 'Not authenticated'}, 401)
            
        token = auth_token.split(' ')[1]
        username = user_manager.validate_session(token)
        if not username:
            return self._json_response({'error': 'Invalid session'}, 401)

        vdiFile = data.get('vdiFile')
        if not vdiFile:
            return self._json_response({'error': 'Missing required field: vdiFile'}, 400)
        
        # Load the VDS profile
        try:
            with open(os.path.join('vdsProfiles', vdiFile)) as f:
                vds_profile = json.load(f)
                vdiUUID = vds_profile['vdsProperties']['uuid']
                expectedCIDR = vds_profile['vdsProperties']['expected_cidr_range']
        except Exception as e:
            return self._json_response({'error': f'Failed to load VDS profile: {str(e)}'}, 400)
            
        # Dev mode - skip Broker execution
        if os.getenv('SKIP_BROKER') == '1':
            return self._json_response({'status': 'dev-skip', 'username': username, 'vdiFile': vdiFile})

        # Execute Broker.py
        try:
            vds_password = user_manager.users[username]['vds_password']
            cmd = ['python3', 'Broker.py', username, vds_password, vdiFile, vdiUUID, expectedCIDR]
            print(f"Executing command: {' '.join(cmd)}")  # Debug output
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
            print(f"Broker output: {proc.stdout}")  # Debug output
            print(f"Broker error: {proc.stderr}")   # Debug output
            
            if proc.returncode != 0:
                error_msg = proc.stdout.strip() or proc.stderr.strip() or "Unknown error occurred"
                return self._json_response({'error': error_msg}, 500)
                
        except Exception as e:
            return self._json_response({'error': f'Failed to execute broker: {str(e)}'}, 500)

        if proc.returncode != 0:
            return self._json_response({'error': 'Broker failed', 'stdout': proc.stdout, 'stderr': proc.stderr}, 500)

        # Parse JSON response from stdout
        try:
            for line in proc.stdout.splitlines():
                if line.startswith('{') and line.endswith('}'):
                    broker_response = json.loads(line)
                    break
            else:
                return self._json_response({'error': 'No valid response from broker'}, 500)
        except Exception as e:
            return self._json_response({'error': 'Invalid response from broker'}, 500)

        if 'connection_id' not in broker_response:
            return self._json_response({'error': 'No connection ID in broker response'}, 500)

        # Create base64-encoded connection string for Guacamole
        import base64
        string_with_nulls = f"{broker_response['connection_id']}\x00c\x00postgresql"
        bytes_to_encode = string_with_nulls.encode('utf-8')
        broker_response['connection_string'] = base64.b64encode(bytes_to_encode).decode('utf-8')

        return self._json_response(broker_response, 200)

    def _json_response(self, obj, status=200):
        try:
            data = json.dumps(obj).encode('utf-8')
            # Only send headers if they haven't been sent already
            if not self.headers_sent:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options', 'DENY')
                self.send_header('Content-Security-Policy', "default-src 'self'")
                self.send_header('X-XSS-Protection', '1; mode=block')
                self.end_headers()
                self.headers_sent = True
            self.wfile.write(data)
            return None  # Prevent double-writing response
        except Exception as e:
            print(f"Error in _json_response: {str(e)}")
            if not self.headers_sent:
                self.send_error(500, f"Internal server error: {str(e)}")

    def handle_users(self):
        try:
            if not self.validate_admin():
                return self._json_response({'error': 'Unauthorized: Admin access required'}, 403)
                
            # Get the current user's username
            auth_token = self.headers.get('Authorization').split(' ')[1]
            current_username = user_manager.validate_session(auth_token)
            
            # Parse request body
            content_length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            
            username = data.get('username')
            password = data.get('password')
            is_admin = data.get('is_admin', False)
            
            if not username or not password:
                return self._json_response({'error': 'Username and password required'}, 400)
                
            success, message = user_manager.add_user(username, password, is_admin)
            if success:
                return self._json_response({'message': message})
            else:
                return self._json_response({'error': message}, 400)
                
        except Exception as e:
            return self._json_response({'error': f'Failed to create user: {str(e)}'}, 500)

    def translate_path(self, path):
        # Log the requested path for debugging
        print(f"Translating path: {path}")
        
        # Serve files from frontend directory by default
        if path == '/' or path == '/index.html':
            # map / to frontend/index.html
            translated = os.path.join(os.getcwd(), FRONTEND_DIR, 'index.html')
        elif path.startswith('/frontend/'):
            # remove leading /frontend/
            rel = path[len('/frontend/'):]
            translated = os.path.join(os.getcwd(), FRONTEND_DIR, rel)
        else:
            # For other paths, try serving from frontend directory first
            translated = os.path.join(os.getcwd(), FRONTEND_DIR, path.lstrip('/'))
            if not os.path.exists(translated):
                # If not found in frontend, fall back to normal behavior
                translated = super().translate_path(path)
                
        print(f"Translated to: {translated}")
        return translated

# Initialize rate limiter and user manager
rate_limiter = RateLimiter()
user_manager = UserManager()

if __name__ == '__main__':
    os.chdir(os.getcwd())
    with socketserver.TCPServer(('0.0.0.0', PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()