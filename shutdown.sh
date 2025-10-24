#!/bin/bash

# XBroker Graceful Shutdown Script
# Sends SIGTERM to running XBroker process for graceful shutdown

set -e

# Find XBroker process
XBROKER_PID=$(pgrep -f "gunicorn.*wsgi:application" | head -n 1)

if [ -z "$XBROKER_PID" ]; then
    echo "ERROR: XBroker process not found"
    exit 1
fi

echo "Initiating graceful shutdown of XBroker (PID: $XBROKER_PID)..."
echo "Sending SIGTERM signal..."

# Send SIGTERM for graceful shutdown
kill -TERM "$XBROKER_PID"

# Wait for graceful shutdown (up to 30 seconds)
TIMEOUT=30
ELAPSED=0

while [ $ELAPSED -lt $TIMEOUT ]; do
    if ! kill -0 "$XBROKER_PID" 2>/dev/null; then
        echo "Shutdown completed successfully"
        exit 0
    fi
    echo -n "."
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

# Force kill if still running
echo ""
echo "Shutdown timeout exceeded, force killing process..."
kill -KILL "$XBROKER_PID" 2>/dev/null || true

sleep 1

if kill -0 "$XBROKER_PID" 2>/dev/null; then
    echo "ERROR: Failed to shutdown XBroker process"
    exit 1
else
    echo "Shutdown completed"
    exit 0
fi
