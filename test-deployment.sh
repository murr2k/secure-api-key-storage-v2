#!/bin/bash

# Quick test script for local deployment

echo "Testing deployment locally..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env from example..."
    cp .env.example .env
    
    # Generate random secrets
    JWT_SECRET=$(openssl rand -hex 32)
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    DB_PASSWORD=$(openssl rand -base64 24)
    REDIS_PASSWORD=$(openssl rand -base64 24)
    MASTER_PASSWORD=$(openssl rand -base64 16)
    ADMIN_PASSWORD=$(openssl rand -base64 16)
    GRAFANA_PASSWORD=$(openssl rand -base64 16)
    
    # Update .env with generated values
    sed -i "s/your_jwt_secret_key_here/$JWT_SECRET/" .env
    sed -i "s/your_encryption_key_here/$ENCRYPTION_KEY/" .env
    sed -i "s/your_secure_database_password/$DB_PASSWORD/" .env
    sed -i "s/your_secure_redis_password/$REDIS_PASSWORD/" .env
    sed -i "s/your_master_password_here/$MASTER_PASSWORD/" .env
    sed -i "s/your_secure_admin_password/$ADMIN_PASSWORD/" .env
    sed -i "s/your_grafana_password/$GRAFANA_PASSWORD/" .env
    
    echo "Generated test credentials:"
    echo "Admin Password: $ADMIN_PASSWORD"
    echo "Master Password: $MASTER_PASSWORD"
fi

# Create necessary directories
mkdir -p data logs backups config docker/ssl

# Test Docker build
echo "Building Docker image (this may take a few minutes)..."
docker build -t secure-api-storage-test .

echo ""
echo "✅ Docker build successful!"
echo ""
echo "To deploy locally, run:"
echo "  ./deploy.sh deploy"
echo ""
echo "To stop and clean up:"
echo "  docker-compose down -v"
echo ""