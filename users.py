import json
import os
import hashlib
import secrets
from datetime import datetime, timedelta

class UserManager:
    def __init__(self):
        self.users_file = 'users.json'
        self.sessions = {}
        self.load_users()

    def load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}
            self.save_users()

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=4)

    def hash_password(self, password):
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256((password + salt).encode())
        return f"{salt}:{hash_obj.hexdigest()}"

    def verify_password(self, stored_hash, password):
        if not stored_hash or ':' not in stored_hash:
            return False
        salt, hash_value = stored_hash.split(':')
        hash_obj = hashlib.sha256((password + salt).encode())
        return hash_obj.hexdigest() == hash_value

    def add_user(self, username, password, is_admin=False):
        if username in self.users:
            return False, "Username already exists"
        
        self.users[username] = {
            'password_hash': self.hash_password(password),
            'vds_password': password,  # Store actual password for VDS access
            'is_admin': is_admin,
            'created_at': datetime.now().isoformat()
        }
        self.save_users()
        return True, "User created successfully"

    def authenticate(self, username, password):
        if username not in self.users:
            return None
        
        if not self.verify_password(self.users[username]['password_hash'], password):
            return None
            
        # Update VDS password on successful login
        self.update_vds_password(username, password)

        # Create session token
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            'username': username,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=12)
        }
        
        return session_token

    def validate_session(self, session_token):
        if session_token not in self.sessions:
            return None
        
        session = self.sessions[session_token]
        if datetime.now() > session['expires_at']:
            del self.sessions[session_token]
            return None
            
        return session['username']

    def logout(self, session_token):
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False
        
    def is_admin(self, username):
        """Check if a user is an admin"""
        return username in self.users and self.users[username].get('is_admin', False)
        
    def update_vds_password(self, username, new_password):
        """Update VDS password for a user"""
        if username in self.users:
            self.users[username]['vds_password'] = new_password
            self.save_users()
            return True
        return False

# Create initial admin user if no users exist
if __name__ == '__main__':
    um = UserManager()
    if not um.users:
        um.add_user('admin', 'admin', True)
        print("Created default admin user (username: admin, password: admin)")