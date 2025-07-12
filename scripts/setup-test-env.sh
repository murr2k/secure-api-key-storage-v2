#!/bin/bash

# Setup Test Environment
# This script sets up the test environment for regression tests

set -e

echo "Setting up test environment..."

# Create test reports directory
mkdir -p test-reports/{backend,frontend,e2e,performance}

# Set test environment variables
export TESTING=true
export DATABASE_URL="postgresql://test_user:test_password@localhost:5433/test_secure_keys"
export REDIS_URL="redis://:test_redis_password@localhost:6380/0"
export MASTER_PASSWORD="test_master_password"
export JWT_SECRET_KEY="test_jwt_secret_key_for_testing_only"
export ENCRYPTION_KEY="test_encryption_key_32_bytes_long"

# Create test data directories
mkdir -p test-data/{keys,backups,logs}

# Set proper permissions
chmod -R 755 test-data/
chmod +x scripts/*.sh

# Generate test certificates for testing
if [ ! -f "test-data/test-cert.pem" ]; then
    echo "Generating test certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout test-data/test-key.pem -out test-data/test-cert.pem -days 365 -nodes -subj "/CN=test.localhost"
fi

echo "Test environment setup complete!"
echo "Test reports will be saved to: $(pwd)/test-reports/"
echo "Test data directory: $(pwd)/test-data/"