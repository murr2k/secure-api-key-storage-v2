#!/bin/bash
set -e

echo "Starting Secure API Key Storage v2..."

# Function to wait for a service
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=0
    
    echo "Waiting for $service on port $port..."
    while ! nc -z localhost $port; do
        attempt=$((attempt + 1))
        if [ $attempt -eq $max_attempts ]; then
            echo "Error: $service did not start in time"
            exit 1
        fi
        echo "Waiting for $service... (attempt $attempt/$max_attempts)"
        sleep 2
    done
    echo "$service is ready!"
}

# Create necessary directories
mkdir -p /data /logs /app/config

# Set proper permissions
chown -R keymanager:keymanager /data /logs /app/config

# Generate self-signed SSL certificates if they don't exist
if [ ! -f /etc/nginx/ssl/cert.pem ]; then
    echo "Generating self-signed SSL certificates..."
    mkdir -p /etc/nginx/ssl 2>/dev/null || true
    if [ -w /etc/nginx/ssl ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/key.pem \
            -out /etc/nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    else
        echo "Warning: Cannot create SSL certificates (permission denied). Using HTTP only."
    fi
fi

# Initialize database if needed
if [ "$DATABASE_URL" ]; then
    echo "Checking database connection..."
    python -c "
import os
import time
from sqlalchemy import create_engine
max_attempts = 30
for i in range(max_attempts):
    try:
        engine = create_engine(os.environ.get('DATABASE_URL'))
        conn = engine.connect()
        conn.close()
        print('Database connection successful!')
        break
    except Exception as e:
        if i == max_attempts - 1:
            print(f'Database connection failed: {e}')
            exit(1)
        print(f'Waiting for database... (attempt {i+1}/{max_attempts})')
        time.sleep(2)
"
    
    # Run database migrations
    echo "Skipping database migrations for now..."
    # cd /app && python -m src.migrate_to_rbac --source /data --destination /data --force
fi

# Set up initial admin user if not exists
if [ "$ADMIN_USERNAME" ] && [ "$ADMIN_PASSWORD" ]; then
    echo "Setting up admin user..."
    python -c "
import os
from src.auth_manager import AuthManager
auth = AuthManager()
try:
    auth.create_user(
        username=os.environ.get('ADMIN_USERNAME', 'admin'),
        password=os.environ.get('ADMIN_PASSWORD'),
        role='admin'
    )
    print('Admin user created successfully!')
except Exception as e:
    print(f'Admin user may already exist: {e}')
"
fi

# Generate JWT secret if not provided
if [ -z "$JWT_SECRET_KEY" ]; then
    export JWT_SECRET_KEY=$(openssl rand -hex 32)
    echo "Generated JWT secret key"
fi

# Generate encryption key if not provided
if [ -z "$ENCRYPTION_KEY" ]; then
    export ENCRYPTION_KEY=$(openssl rand -hex 32)
    echo "Generated encryption key"
fi

# Export environment variables for all processes
export PYTHONPATH=/app:$PYTHONPATH
export NODE_ENV=production
export SECURE_STORAGE_PATH=/data
export LOG_PATH=/logs

# Create config file with current settings
cat > /app/config/runtime.env << EOF
API_URL=${API_URL:-http://localhost:8000}
FRONTEND_URL=${FRONTEND_URL:-http://localhost:3000}
DATABASE_URL=${DATABASE_URL}
REDIS_URL=${REDIS_URL}
JWT_SECRET_KEY=${JWT_SECRET_KEY}
ENCRYPTION_KEY=${ENCRYPTION_KEY}
LOG_LEVEL=${LOG_LEVEL:-info}
EOF

# Start health check endpoint early
# Disabled to avoid port conflict
# python -c "
# from fastapi import FastAPI
# import uvicorn
# app = FastAPI()
# @app.get('/health')
# def health():
#     return {'status': 'starting'}
# if __name__ == '__main__':
#     uvicorn.run(app, host='0.0.0.0', port=8001)
# " &

# Build frontend if needed
if [ ! -d /app/dashboard/frontend/.next ]; then
    echo "Building frontend..."
    cd /app/dashboard/frontend && npm run build
fi

# Start supervisord
echo "Starting supervisord..."
exec "$@"