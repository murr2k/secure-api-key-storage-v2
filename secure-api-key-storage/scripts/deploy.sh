#!/bin/bash
# Production Deployment Script for Secure API Key Storage

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root!"
   exit 1
fi

# Check if .env.production exists
if [ ! -f .env.production ]; then
    error ".env.production file not found!"
    error "Please copy .env.production.example to .env.production and configure it."
    exit 1
fi

log "🚀 Starting deployment of Secure API Key Storage"

# Load environment variables
log "Loading environment variables..."
source .env.production

# Validate required environment variables
required_vars=("MASTER_PASSWORD" "DB_PASSWORD" "REDIS_PASSWORD" "JWT_SECRET_KEY" "DOMAIN")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        error "Required environment variable $var is not set!"
        exit 1
    fi
done

# Create required directories
log "Creating required directories..."
mkdir -p keys backups logs nginx/cache config

# Set proper permissions
log "Setting file permissions..."
chmod 700 keys backups
chmod 755 logs nginx config

# Pull latest images
log "📦 Pulling latest Docker images..."
docker-compose -f docker-compose.production.yml pull

# Stop existing containers
log "🛑 Stopping existing containers..."
docker-compose -f docker-compose.production.yml down

# Remove old containers and networks
log "Cleaning up old resources..."
docker system prune -f

# Start services
log "▶️ Starting services..."
docker-compose -f docker-compose.production.yml up -d

# Wait for database to be ready
log "⏳ Waiting for database to be ready..."
sleep 10

# Check if services are healthy
log "🏥 Checking service health..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if docker-compose -f docker-compose.production.yml ps | grep -q "healthy"; then
        log "Services are healthy!"
        break
    fi
    
    warning "Waiting for services to become healthy... (attempt $attempt/$max_attempts)"
    sleep 5
    ((attempt++))
done

if [ $attempt -gt $max_attempts ]; then
    error "Services failed to become healthy after $max_attempts attempts"
    docker-compose -f docker-compose.production.yml logs
    exit 1
fi

# Run database migrations (if any)
log "Running database migrations..."
# docker-compose -f docker-compose.production.yml exec -T secure-key-storage python manage.py migrate

# Test the application
log "🧪 Testing application endpoints..."

# Test health endpoint
if curl -f -s "https://${DOMAIN}/api/health" > /dev/null; then
    log "✅ Health check passed!"
else
    warning "Health check failed via HTTPS, trying HTTP..."
    if curl -f -s "http://localhost:8000/api/health" > /dev/null; then
        log "✅ Health check passed via HTTP!"
    else
        error "Health check failed!"
        docker-compose -f docker-compose.production.yml logs secure-key-storage
        exit 1
    fi
fi

# Show running services
log "📊 Running services:"
docker-compose -f docker-compose.production.yml ps

# Create initial backup
log "📦 Creating initial backup..."
./scripts/backup.sh

log "✅ Deployment completed successfully!"
log ""
log "🌐 Access your application at: https://${DOMAIN}"
log "📊 View logs: docker-compose -f docker-compose.production.yml logs -f"
log "🔄 Restart services: docker-compose -f docker-compose.production.yml restart"