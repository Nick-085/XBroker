"""
Audit logging module for XBroker - tracks user actions and system events
"""
import json
import sqlite3
from datetime import datetime
import os
from pathlib import Path

class AuditLogger:
    """Audit logger that stores events in database"""
    
    def __init__(self, db_file='users.db'):
        self.db_file = db_file
        self.init_db()
    
    def init_db(self):
        """Initialize audit log table"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    status TEXT,
                    details TEXT,
                    ip_address TEXT
                )
            ''')
            
            # Create index for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_username 
                ON audit_logs(username)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_logs(timestamp)
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error initializing audit log database: {str(e)}")
    
    def log(self, username, action, resource=None, status='success', details=None, ip_address=None):
        """Log an audit event"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            details_json = json.dumps(details) if details else None
            
            cursor.execute('''
                INSERT INTO audit_logs 
                (username, action, resource, status, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, action, resource, status, details_json, ip_address))
            
            conn.commit()
            conn.close()
            
            # Also log to console for real-time monitoring
            timestamp = datetime.now().isoformat()
            print(f"[AUDIT] {timestamp} | User: {username} | Action: {action} | Resource: {resource} | Status: {status} | IP: {ip_address}")
        
        except Exception as e:
            print(f"Error writing to audit log: {str(e)}")
    
    def get_logs(self, username=None, action=None, limit=100, offset=0):
        """Retrieve audit logs with optional filtering"""
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []
            
            if username:
                query += " AND username = ?"
                params.append(username)
            
            if action:
                query += " AND action = ?"
                params.append(action)
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            logs = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return logs
        
        except Exception as e:
            print(f"Error retrieving audit logs: {str(e)}")
            return []
    
    def get_user_activity_summary(self, username, days=30):
        """Get activity summary for a user over the past N days"""
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    action,
                    COUNT(*) as count,
                    COUNT(CASE WHEN status = 'success' THEN 1 END) as successful,
                    COUNT(CASE WHEN status = 'failure' THEN 1 END) as failed
                FROM audit_logs
                WHERE username = ? 
                AND timestamp >= datetime('now', '-' || ? || ' days')
                GROUP BY action
            ''', (username, days))
            
            summary = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return summary
        
        except Exception as e:
            print(f"Error getting activity summary: {str(e)}")
            return []
    
    def cleanup_old_logs(self, days=90):
        """Remove audit logs older than N days"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM audit_logs
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            print(f"Cleaned up {deleted} old audit log entries (older than {days} days)")
            return deleted
        
        except Exception as e:
            print(f"Error cleaning up audit logs: {str(e)}")
            return 0

# Initialize global audit logger
audit_logger = AuditLogger()
