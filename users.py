import os
import sqlite3
import secrets
import bcrypt
import pyotp
import qrcode
from io import StringIO
from datetime import datetime, timedelta
from contextlib import contextmanager

class UserManager:
    def __init__(self):
        self.db_file = 'users.db'
        self.sessions = {}
        self.init_db()

    @contextmanager
    def get_db(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self):
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Create users table with all required columns
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    vds_password TEXT NOT NULL,
                    admin_level INTEGER NOT NULL DEFAULT 0,
                    is_locked BOOLEAN NOT NULL DEFAULT 0,
                    totp_secret TEXT,
                    totp_enabled BOOLEAN NOT NULL DEFAULT 0,
                    first_login BOOLEAN NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Migration: update existing tables to use admin_level
            # Check if is_admin column exists and migrate if needed
            cursor.execute("PRAGMA table_info(users)")
            columns = {col[1] for col in cursor.fetchall()}
            
            # Only migrate if is_admin exists and admin_level doesn't
            if 'is_admin' in columns and 'admin_level' not in columns:
                # Add admin_level column
                cursor.execute('''
                    ALTER TABLE users ADD COLUMN admin_level INTEGER DEFAULT 0
                ''')
                # Migrate existing admins to global_admin (level 3)
                cursor.execute('''
                    UPDATE users SET admin_level = 3 WHERE is_admin = 1
                ''')
                conn.commit()
                print("Migrated admin_level from is_admin column")
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (username) REFERENCES users (username)
                )
            ''')
            conn.commit()

    def hash_password(self, password):
        print(f"Hashing password...")
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        result = hashed.decode()
        print(f"Generated hash length: {len(result)}")
        return result

    def verify_password(self, stored_hash, password):
        try:
            print(f"Verifying password (stored hash length: {len(stored_hash)})")
            encoded_pass = password.encode()
            encoded_hash = stored_hash.encode()
            result = bcrypt.checkpw(encoded_pass, encoded_hash)
            print(f"Password check result: {result}")
            return result
        except Exception as e:
            print(f"Password verification error: {str(e)}")
            return False

    def add_user(self, username, password, admin_level=0):
        """Add a new user with a specified admin level.
        
        Admin levels:
        0 = Regular user
        1 = User admin (can manage users)
        2 = VDI admin (can manage VDI configurations)
        3 = Global admin (can manage both users and VDI configs)
        """
        with self.get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cursor.fetchone():
                    return False, "Username already exists"
                
                # Validate admin_level
                if admin_level not in [0, 1, 2, 3]:
                    return False, "Invalid admin level"
                
                cursor.execute('''
                    INSERT INTO users (username, password_hash, vds_password, admin_level)
                    VALUES (?, ?, ?, ?)
                ''', (username, self.hash_password(password), password, admin_level))
                conn.commit()
                return True, "User created successfully"
            except sqlite3.Error as e:
                conn.rollback()
                return False, f"Database error: {str(e)}"

    def authenticate(self, username, password, totp_code=None):
        print(f"Authenticating user: {username}")
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT password_hash, is_locked, totp_enabled, first_login 
                FROM users WHERE username = ?
            ''', (username,))
            user = cursor.fetchone()
            
            if not user:
                print(f"User not found: {username}")
                return None
                
            is_password_valid = self.verify_password(user['password_hash'], password)
            print(f"Password verification result: {is_password_valid}")
            
            if not is_password_valid:
                return None
                
            if user['is_locked']:
                return 'ACCOUNT_LOCKED'
                
            # Force 2FA setup on first login
            if user['first_login']:
                # Store the credentials temporarily and initiate 2FA setup
                return 'NEEDS_2FA_SETUP'
                
            # Check 2FA for subsequent logins
            if user['totp_enabled']:
                if not totp_code:
                    return 'NEEDS_2FA'
                if not self.verify_2fa(username, totp_code):
                    return None
            
            # Update VDS password on successful login
            self.update_vds_password(username, password)

            # Create session token and store in database
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=12)
            
            cursor.execute('''
                INSERT INTO sessions (token, username, expires_at)
                VALUES (?, ?, ?)
            ''', (session_token, username, expires_at))
            conn.commit()
            
            return session_token

    def validate_session(self, session_token):
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, expires_at FROM sessions 
                WHERE token = ?
            ''', (session_token,))
            session = cursor.fetchone()
            
            if not session:
                return None
                
            if datetime.now() > datetime.fromisoformat(session['expires_at']):
                cursor.execute('DELETE FROM sessions WHERE token = ?', (session_token,))
                conn.commit()
                return None
                
            return session['username']

    def logout(self, session_token):
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE token = ?', (session_token,))
            conn.commit()
            return cursor.rowcount > 0

    def is_admin(self, username):
        """Check if a user is any type of admin"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT admin_level FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return bool(result and result['admin_level'] > 0)
    
    def get_admin_level(self, username):
        """Get the admin level for a user.
        
        Returns:
        0 = Regular user
        1 = User admin (can manage users)
        2 = VDI admin (can manage VDI configurations)
        3 = Global admin (can manage both users and VDI configs)
        """
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT admin_level FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return result['admin_level'] if result else 0
    
    def is_user_admin(self, username):
        """Check if user can manage users (level 1 or 3)"""
        admin_level = self.get_admin_level(username)
        return admin_level in [1, 3]
    
    def is_vdi_admin(self, username):
        """Check if user can manage VDI configurations (level 2 or 3)"""
        admin_level = self.get_admin_level(username)
        return admin_level in [2, 3]
    
    def is_global_admin(self, username):
        """Check if user is a global admin (level 3)"""
        admin_level = self.get_admin_level(username)
        return admin_level == 3
    
    def set_admin_level(self, username, admin_level):
        """Update a user's admin level"""
        if admin_level not in [0, 1, 2, 3]:
            return False, "Invalid admin level"
        
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET admin_level = ?
                WHERE username = ?
            ''', (admin_level, username))
            conn.commit()
            return cursor.rowcount > 0, "Admin level updated successfully"

    def update_vds_password(self, username, new_password):
        """Update VDS password for a user"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET vds_password = ?
                WHERE username = ?
            ''', (new_password, username))
            conn.commit()
            return cursor.rowcount > 0
            
    def delete_user(self, username):
        """Delete a user from the database"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE username = ?', (username,))
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            return cursor.rowcount > 0
            
    def set_account_lock(self, username, locked):
        """Lock or unlock a user account"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET is_locked = ?
                WHERE username = ?
            ''', (locked, username))
            if locked:
                # Remove all active sessions for the locked user
                cursor.execute('DELETE FROM sessions WHERE username = ?', (username,))
            conn.commit()
            return cursor.rowcount > 0
            
    def change_user_password(self, username, new_password, admin_action=False):
        """Change a user's password
        
        Args:
            username: The username whose password to change
            new_password: The new password
            admin_action: If True, also updates VDS password. If False, only updates login password.
        """
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?
                    {vds_update}
                WHERE username = ?
            '''.format(
                vds_update=", vds_password = ?" if admin_action else ""
            ), (
                self.hash_password(new_password),
                *([new_password] if admin_action else []),
                username
            ))
            if cursor.rowcount > 0:
                # Remove all active sessions for the user
                cursor.execute('DELETE FROM sessions WHERE username = ?', (username,))
                conn.commit()
                return True
            return False
            
    def is_locked(self, username):
        """Check if a user account is locked"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT is_locked FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return bool(result and result['is_locked'])
            
    def get_vds_password(self, username):
        """Get the VDS password for a user"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT vds_password FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return result['vds_password'] if result else None

    def setup_2fa(self, username):
        """Set up 2FA for a user. Returns (secret, provisioning URI, qr_code)"""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(username, issuer_name="XBroker")
        
        # Generate QR code as base64 image
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image and convert to base64
        import io
        import base64
        from PIL import Image
        
        # Create PIL image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        # Store the secret in the database
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET totp_secret = ?, totp_enabled = 0
                WHERE username = ?
            ''', (secret, username))
            conn.commit()
        
        return secret, provisioning_uri, f"data:image/png;base64,{qr_code_base64}"
        
    def verify_2fa(self, username, code):
        """Verify a 2FA code"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT totp_secret FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if not result or not result['totp_secret']:
                return False
            
            totp = pyotp.TOTP(result['totp_secret'])
            return totp.verify(code)
            
    def enable_2fa(self, username, code):
        """Enable 2FA after verifying the setup code"""
        if self.verify_2fa(username, code):
            with self.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE users 
                    SET totp_enabled = 1,
                        first_login = 0
                    WHERE username = ?
                ''', (username,))
                conn.commit()
            return True
        return False
        
    def disable_2fa(self, username):
        """Disable 2FA for a user"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET totp_secret = NULL, totp_enabled = 0
                WHERE username = ?
            ''', (username,))
            conn.commit()
        return True
        
    def is_2fa_enabled(self, username):
        """Check if 2FA is enabled for a user"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT totp_enabled FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            return bool(result and result['totp_enabled'])

    def verify_password_for_user(self, username, password):
        """Verify a user's password (for current password verification)"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if not result:
                return False
            return self.verify_password(result['password_hash'], password)

    def change_password(self, username, new_password):
        """Change a user's password"""
        try:
            new_hash = self.hash_password(new_password)
            with self.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE users 
                    SET password_hash = ?
                    WHERE username = ?
                ''', (new_hash, username))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return False

# Create initial admin user if no users exist
if __name__ == '__main__':
    um = UserManager()
    with um.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM users')
        if cursor.fetchone()['count'] == 0:
            um.add_user('admin', 'admin', True)
            print("Created default admin user (username: admin, password: admin)")