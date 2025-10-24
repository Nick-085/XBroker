#!/bin/bash

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

# Set default values if not in environment
export PORT=${PORT:-8000}
export WORKERS=${WORKERS:-2}
export TIMEOUT=${TIMEOUT:-120}

# TLS Configuration (for direct HTTPS, leave unset if behind reverse proxy)
export TLS_ENABLED=${TLS_ENABLED:-true}
export REVERSE_PROXY_ENABLED=${REVERSE_PROXY_ENABLED:-true}
export TLS_CERT_PATH=${TLS_CERT_PATH:-./certs/server.crt}
export TLS_KEY_PATH=${TLS_KEY_PATH:-./certs/server.key}
export TLS_MIN_VERSION=${TLS_MIN_VERSION:-TLSv1.2}

# Auto-generate certificates if TLS is enabled but certs don't exist or expiring within 10 days
if [ "$TLS_ENABLED" = "true" ]; then
    NEED_CERT=false
    
    # Check if certificates exist
    if [ ! -f "$TLS_CERT_PATH" ] || [ ! -f "$TLS_KEY_PATH" ]; then
        NEED_CERT=true
    else
        # Check if certificate is expiring within 10 days
        EXPIRY_DAYS=$(python3 -c "
import sys
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import datetime
    with open('$TLS_CERT_PATH', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    days_left = (cert.not_valid_after - datetime.datetime.utcnow()).days
    print(days_left)
except:
    print(-1)
" 2>/dev/null)
        
        if [ "$EXPIRY_DAYS" -lt 10 ] 2>/dev/null; then
            NEED_CERT=true
        else
            echo "cert found"
        fi
    fi
    
    # Generate if needed
    if [ "$NEED_CERT" = "true" ]; then
        CERT_HOSTNAME=${HOSTNAME:-xbroker}
        python3 tls_config.py generate "$CERT_HOSTNAME" 2>&1 | grep -v "DeprecationWarning" > /dev/null
        
        if [ -f "$TLS_CERT_PATH" ] && [ -f "$TLS_KEY_PATH" ]; then
            echo "cert generated"
        else
            echo "ERROR: Failed to generate certificates"
            exit 1
        fi
    fi
fi

# Start the session cleaner in the background
nohup python3 cleanStaleSessions.py > /dev/null 2>&1 &

# Start Gunicorn with environment variables for configuration
# Redirect ERROR-level worker messages that don't indicate real problems
exec 2> >(grep -v "Worker (pid:" || cat)

# Build gunicorn command
GUNICORN_ARGS=(
    wsgi:application
    --bind "0.0.0.0:$PORT"
    --workers "$WORKERS"
    --timeout "$TIMEOUT"
    --max-requests 1000
    --max-requests-jitter 50
    --keep-alive 5
    --access-logfile -
    --error-logfile -
    --log-level warning
    --worker-class sync
)

# Add TLS/SSL configuration if enabled
if [ "$TLS_ENABLED" = "true" ] && [ -f "$TLS_CERT_PATH" ] && [ -f "$TLS_KEY_PATH" ]; then
    GUNICORN_ARGS+=(
        --certfile "$TLS_CERT_PATH"
        --keyfile "$TLS_KEY_PATH"
    )
    echo "Starting with HTTPS enabled (TLS $TLS_MIN_VERSION)"
else
    echo "Starting in HTTP mode"
    if [ "$REVERSE_PROXY_ENABLED" = "true" ]; then
        echo "Reverse proxy header handling is enabled"
        echo "Make sure your reverse proxy is setting X-Forwarded-* headers"
    fi
fi

exec gunicorn "${GUNICORN_ARGS[@]}"