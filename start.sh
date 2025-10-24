#!/bin/bash

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

# Set default values if not in environment
export PORT=${PORT:-8000}
export WORKERS=${WORKERS:-2}
export TIMEOUT=${TIMEOUT:-120}

# Start the session cleaner in the background
nohup python3 cleanStaleSessions.py > /dev/null 2>&1 &

# Start Gunicorn with environment variables for configuration
# Redirect ERROR-level worker messages that don't indicate real problems
exec 2> >(grep -v "Worker (pid:" || cat) 

exec gunicorn wsgi:application \
    --bind 0.0.0.0:$PORT \
    --workers $WORKERS \
    --timeout $TIMEOUT \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    --log-level warning \
    --worker-class sync