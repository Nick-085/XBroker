#!/usr/bin/env python3
"""
TLS Configuration Module for XBroker

This module handles SSL/TLS certificate management and configuration for Gunicorn.
Supports both direct HTTPS and reverse proxy scenarios with proper header handling.

Key Features:
- Certificate validation and loading
- Environment variable support for flexible deployment
- Reverse proxy header handling (X-Forwarded-Proto, X-Forwarded-For, etc.)
- Certificate rotation detection
- Development self-signed certificate generation
"""

import os
import ssl
import logging
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress

logger = logging.getLogger(__name__)


class TLSConfig:
    """
    Manages TLS/SSL configuration for the application.
    
    Environment Variables:
    - TLS_ENABLED: Enable HTTPS (default: true) - Security-first approach
    - TLS_CERT_PATH: Path to SSL certificate file (default: ./certs/server.crt)
    - TLS_KEY_PATH: Path to SSL key file (default: ./certs/server.key)
    - TLS_CERT_CHAIN_PATH: Optional path to certificate chain file
    - TLS_MIN_VERSION: Minimum TLS version (TLSv1.2 or TLSv1.3, default: TLSv1.2)
    - TLS_CIPHERS: Custom cipher suite (optional)
    - REVERSE_PROXY_ENABLED: Enable reverse proxy header handling (default: true)
    - GUNICORN_CERTFILE: Alternative name for cert path (used in start.sh)
    - GUNICORN_KEYFILE: Alternative name for key path (used in start.sh)
    """
    
    def __init__(self):
        # Default to HTTPS enabled for security-first approach
        self.enabled = self._str_to_bool(os.getenv('TLS_ENABLED', 'true'))
        self.cert_path = os.getenv('TLS_CERT_PATH', os.getenv('GUNICORN_CERTFILE', './certs/server.crt'))
        self.key_path = os.getenv('TLS_KEY_PATH', os.getenv('GUNICORN_KEYFILE', './certs/server.key'))
        self.cert_chain_path = os.getenv('TLS_CERT_CHAIN_PATH', None)
        self.reverse_proxy_enabled = self._str_to_bool(os.getenv('REVERSE_PROXY_ENABLED', 'true'))
        self.min_version = os.getenv('TLS_MIN_VERSION', 'TLSv1.2')
        self.ciphers = os.getenv('TLS_CIPHERS', None)
        
        # Validate configuration
        self._validate_config()
    
    @staticmethod
    def _str_to_bool(value):
        """Convert string to boolean."""
        return value.lower() in ('true', '1', 'yes', 'on')
    
    def _validate_config(self):
        """Validate TLS configuration."""
        if not self.enabled:
            logger.info("TLS is disabled - running in HTTP mode")
            return
        
        # Check certificate and key files exist
        if not os.path.exists(self.cert_path):
            logger.warning(f"Certificate file not found: {self.cert_path}")
            logger.info("HTTPS may not work properly. Please provide valid certificate.")
        
        if not os.path.exists(self.key_path):
            logger.warning(f"Key file not found: {self.key_path}")
            logger.info("HTTPS may not work properly. Please provide valid key.")
        
        # Validate TLS version
        valid_versions = ('TLSv1.2', 'TLSv1.3')
        if self.min_version not in valid_versions:
            logger.warning(f"Invalid TLS version: {self.min_version}. Using TLSv1.2")
            self.min_version = 'TLSv1.2'
    
    def get_gunicorn_args(self):
        """
        Generate Gunicorn command-line arguments for HTTPS.
        
        Returns:
            dict: Arguments for Gunicorn SSL configuration
        """
        if not self.enabled or not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            return {}
        
        args = {
            'certfile': self.cert_path,
            'keyfile': self.key_path,
        }
        
        if self.cert_chain_path and os.path.exists(self.cert_chain_path):
            args['ca_certs'] = self.cert_chain_path
        
        if self.ciphers:
            args['ciphers'] = self.ciphers
        
        return args
    
    def get_ssl_context(self):
        """
        Create an SSL context for direct HTTPS connections.
        
        Returns:
            ssl.SSLContext or None: Configured SSL context if HTTPS is enabled and certs exist
        """
        if not self.enabled or not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            return None
        
        # Create SSL context
        ssl_version = ssl.PROTOCOL_TLSv1_2 if self.min_version == 'TLSv1.2' else ssl.PROTOCOL_TLSv1_3
        context = ssl.SSLContext(ssl_version)
        
        # Load certificate and key
        context.load_cert_chain(self.cert_path, self.key_path)
        
        # Set secure options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        
        # Set strong cipher suite if not using TLS 1.3 only
        if self.min_version == 'TLSv1.2':
            context.set_ciphers(self.ciphers or 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context
    
    def get_certificate_info(self):
        """
        Get information about the current certificate.
        
        Returns:
            dict: Certificate information including subject, issuer, and expiration
        """
        if not os.path.exists(self.cert_path):
            return None
        
        try:
            with open(self.cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            return {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'issued': cert.not_valid_before.isoformat(),
                'expires': cert.not_valid_after.isoformat(),
                'days_until_expiry': (cert.not_valid_after - datetime.utcnow()).days,
                'san': self._get_san(cert),
            }
        except Exception as e:
            logger.error(f"Error reading certificate: {e}")
            return None
    
    @staticmethod
    def _get_san(cert):
        """Extract Subject Alternative Names from certificate."""
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            return []
    
    def is_certificate_expiring_soon(self, days=30):
        """
        Check if certificate is expiring within the specified number of days.
        
        Args:
            days (int): Number of days to check ahead (default: 30)
            
        Returns:
            bool: True if certificate expires within the specified period
        """
        cert_info = self.get_certificate_info()
        if not cert_info:
            return False
        
        return cert_info['days_until_expiry'] <= days
    
    @staticmethod
    def generate_self_signed_cert(cert_path, key_path, days=365, hostname='localhost'):
        """
        Generate a self-signed certificate for development/testing.
        
        Args:
            cert_path (str): Path to save certificate
            key_path (str): Path to save private key
            days (int): Certificate validity in days (default: 365)
            hostname (str): Hostname for the certificate (default: localhost)
        
        Returns:
            bool: True if certificate was generated successfully
        """
        try:
            # Create certificates directory if it doesn't exist
            cert_dir = os.path.dirname(cert_path)
            if cert_dir and not os.path.exists(cert_dir):
                os.makedirs(cert_dir, mode=0o700)
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Development"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Development"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"XBroker"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName('*.local'),
                    x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Write certificate
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            os.chmod(cert_path, 0o644)
            
            # Write key
            with open(key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(key_path, 0o600)
            
            logger.info(f"Generated self-signed certificate: {cert_path}")
            logger.info(f"Generated private key: {key_path}")
            logger.warning("Self-signed certificates are for development only. Use proper certificates in production.")
            
            return True
        except Exception as e:
            logger.error(f"Error generating self-signed certificate: {e}")
            return False


class ReverseProxyHeaders:
    """
    Manages X-Forwarded-* headers for reverse proxy scenarios.
    
    When behind a reverse proxy (nginx, Apache, HAProxy, etc.), the proxy
    should set these headers to indicate the original client information:
    - X-Forwarded-For: Original client IP
    - X-Forwarded-Proto: Original protocol (http or https)
    - X-Forwarded-Host: Original host
    - X-Forwarded-Port: Original port
    
    Example nginx configuration:
    ```
    location / {
        proxy_pass http://xbroker:8000;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header X-Real-IP $remote_addr;
    }
    ```
    """
    
    @staticmethod
    def get_client_ip(request):
        """
        Get client IP from request, checking X-Forwarded-For if behind proxy.
        
        Args:
            request: Flask request object
            
        Returns:
            str: Client IP address
        """
        if 'X-Forwarded-For' in request.headers:
            # X-Forwarded-For can contain multiple IPs, use the first
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        return request.remote_addr
    
    @staticmethod
    def get_protocol(request):
        """
        Get original protocol from request.
        
        Args:
            request: Flask request object
            
        Returns:
            str: 'https' or 'http'
        """
        if 'X-Forwarded-Proto' in request.headers:
            return request.headers.get('X-Forwarded-Proto').lower()
        return request.scheme
    
    @staticmethod
    def is_https(request):
        """
        Check if original request was HTTPS.
        
        Args:
            request: Flask request object
            
        Returns:
            bool: True if original request was HTTPS
        """
        return ReverseProxyHeaders.get_protocol(request) == 'https'
    
    @staticmethod
    def get_host(request):
        """
        Get original host from request.
        
        Args:
            request: Flask request object
            
        Returns:
            str: Original host header value
        """
        if 'X-Forwarded-Host' in request.headers:
            return request.headers.get('X-Forwarded-Host')
        return request.host
    
    @staticmethod
    def get_url_root(request):
        """
        Get the proper URL root considering reverse proxy.
        
        Args:
            request: Flask request object
            
        Returns:
            str: Proper URL root (scheme://host:port)
        """
        protocol = ReverseProxyHeaders.get_protocol(request)
        host = ReverseProxyHeaders.get_host(request)
        
        # Default ports
        default_port = 443 if protocol == 'https' else 80
        
        # Check X-Forwarded-Port
        if 'X-Forwarded-Port' in request.headers:
            port = request.headers.get('X-Forwarded-Port')
            if port != str(default_port):
                host = f"{host}:{port}"
        
        return f"{protocol}://{host}"


# Configuration for Flask app
def configure_reverse_proxy_headers(app):
    """
    Configure Flask app to handle reverse proxy headers properly.
    
    This should be called before registering routes.
    
    Args:
        app: Flask application instance
    """
    # Trust X-Forwarded-* headers from reverse proxies
    # This is safe if you're using a reverse proxy in front of your app
    from werkzeug.middleware.proxy_fix import ProxyFix
    
    # Configure to trust the proxy headers
    # Adjust according to your reverse proxy setup:
    # - x_for: number of proxies that set X-Forwarded-For
    # - x_proto: number of proxies that set X-Forwarded-Proto
    # - x_host: number of proxies that set X-Forwarded-Host
    # - x_port: number of proxies that set X-Forwarded-Port
    # - x_prefix: number of proxies that set X-Forwarded-Prefix
    
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,        # Trust 1 proxy (your reverse proxy)
        x_proto=1,
        x_host=1,
        x_port=1,
        x_prefix=1
    )
    
    logger.info("Reverse proxy header handling enabled")


def get_tls_config():
    """Get TLS configuration singleton."""
    return TLSConfig()


if __name__ == '__main__':
    # CLI for certificate management
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'generate':
            hostname = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
            cert_path = './certs/server.crt'
            key_path = './certs/server.key'
            TLSConfig.generate_self_signed_cert(cert_path, key_path, hostname=hostname)
            print(f"Certificate generated: {cert_path}")
            print(f"Key generated: {key_path}")
        
        elif command == 'info':
            config = TLSConfig()
            cert_info = config.get_certificate_info()
            if cert_info:
                print("Certificate Information:")
                print(f"  Subject: {cert_info['subject']}")
                print(f"  Issuer: {cert_info['issuer']}")
                print(f"  Issued: {cert_info['issued']}")
                print(f"  Expires: {cert_info['expires']}")
                print(f"  Days until expiry: {cert_info['days_until_expiry']}")
                if cert_info['san']:
                    print(f"  SANs: {', '.join(str(s) for s in cert_info['san'])}")
            else:
                print("No certificate found")
        
        elif command == 'check':
            config = TLSConfig()
            if config.is_certificate_expiring_soon(days=30):
                print("WARNING: Certificate is expiring within 30 days!")
                sys.exit(1)
            else:
                print("Certificate is valid")
        
        else:
            print(f"Unknown command: {command}")
            print("Available commands: generate, info, check")
    else:
        config = TLSConfig()
        print(f"TLS Enabled: {config.enabled}")
        print(f"Certificate: {config.cert_path}")
        print(f"Key: {config.key_path}")
        print(f"Reverse Proxy: {config.reverse_proxy_enabled}")
