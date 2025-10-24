"""
Input validation and sanitization module for XBroker
"""
import re
import os
from pathlib import Path

class ValidationError(Exception):
    """Custom validation error exception"""
    pass

def validate_username(username):
    """Validate username format"""
    if not username or not isinstance(username, str):
        raise ValidationError("Username must be a non-empty string")
    
    if len(username) < 3 or len(username) > 64:
        raise ValidationError("Username must be between 3 and 64 characters")
    
    # Allow alphanumeric, dots, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValidationError("Username can only contain letters, numbers, dots, hyphens, and underscores")
    
    return username.strip()

def validate_password(password):
    """Validate password strength"""
    if not password or not isinstance(password, str):
        raise ValidationError("Password must be a non-empty string")
    
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    
    if len(password) > 256:
        raise ValidationError("Password is too long (max 256 characters)")
    
    return password

def validate_admin_level(level):
    """Validate admin level"""
    try:
        level = int(level)
    except (TypeError, ValueError):
        raise ValidationError("Admin level must be an integer")
    
    if level not in [0, 1, 2, 3]:
        raise ValidationError("Admin level must be 0, 1, 2, or 3")
    
    return level

def validate_filename(filename, allowed_extensions=None):
    """Validate filename to prevent directory traversal"""
    if not filename or not isinstance(filename, str):
        raise ValidationError("Filename must be a non-empty string")
    
    # Prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        raise ValidationError("Invalid filename: directory traversal detected")
    
    # Check for null bytes
    if '\x00' in filename:
        raise ValidationError("Invalid filename: contains null bytes")
    
    # Validate length
    if len(filename) > 255:
        raise ValidationError("Filename is too long (max 255 characters)")
    
    # Check extension if specified
    if allowed_extensions:
        _, ext = os.path.splitext(filename)
        if ext.lower() not in [e.lower() if e.startswith('.') else f'.{e}' for e in allowed_extensions]:
            raise ValidationError(f"File extension not allowed. Allowed: {', '.join(allowed_extensions)}")
    
    return filename.strip()

def validate_json_data(data, required_fields=None, optional_fields=None):
    """Validate JSON data structure"""
    if not isinstance(data, dict):
        raise ValidationError("Data must be a JSON object")
    
    # Check required fields
    if required_fields:
        for field in required_fields:
            if field not in data:
                raise ValidationError(f"Missing required field: {field}")
            if data[field] is None or (isinstance(data[field], str) and not data[field].strip()):
                raise ValidationError(f"Field '{field}' cannot be empty")
    
    # Check for unexpected fields (security: prevent injection of admin fields)
    if optional_fields:
        allowed = set(required_fields or []) | set(optional_fields or [])
        for key in data.keys():
            if key not in allowed:
                raise ValidationError(f"Unexpected field: {key}")
    
    return data

def sanitize_string(value, max_length=500):
    """Sanitize and truncate user input strings"""
    if not isinstance(value, str):
        return str(value)[:max_length]
    
    # Remove control characters but keep normal whitespace
    sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')
    
    return sanitized[:max_length].strip()

def validate_ip_address(ip_string):
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_string)
        return ip_string
    except ValueError:
        raise ValidationError(f"Invalid IP address: {ip_string}")

def validate_cidr_range(cidr_string):
    """Validate CIDR notation"""
    import ipaddress
    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return cidr_string
    except ValueError:
        raise ValidationError(f"Invalid CIDR range: {cidr_string}")

def validate_uuid(uuid_string):
    """Validate UUID format"""
    import uuid
    try:
        uuid.UUID(uuid_string)
        return uuid_string
    except ValueError:
        raise ValidationError(f"Invalid UUID format: {uuid_string}")
