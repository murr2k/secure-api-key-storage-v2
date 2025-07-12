#!/bin/bash

# Comprehensive test runner script
# This script runs all types of tests in the correct order

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_ENV_FILE=".env.test"
TEST_REPORTS_DIR="test-reports"
PROJECT_ROOT="$(pwd)"

echo -e "${YELLOW}🚀 Starting comprehensive test suite...${NC}"

# Create test environment file
create_test_env() {
    echo -e "${YELLOW}📝 Creating test environment configuration...${NC}"
    
    cat > "$TEST_ENV_FILE" << EOF
# Test Environment Configuration
TESTING=true
NODE_ENV=test
PYTHON_ENV=test

# Database configuration
DATABASE_URL=postgresql://test_user:test_password@localhost:5433/test_secure_keys
REDIS_URL=redis://:test_redis_password@localhost:6380/0

# Security configuration
MASTER_PASSWORD=test_master_password
JWT_SECRET_KEY=test_jwt_secret_key_for_testing_only
ENCRYPTION_KEY=test_encryption_key_32_bytes_long

# Disable external services
ENABLE_NOTIFICATIONS=false
ENABLE_BACKUPS=false
ENABLE_MONITORING=false

# Logging
LOG_LEVEL=DEBUG

# Frontend testing
NEXT_PUBLIC_API_URL=http://localhost:8000
EOF
}

# Setup test environment
setup_test_env() {
    echo -e "${YELLOW}🔧 Setting up test environment...${NC}"
    
    # Create test reports directory
    mkdir -p "$TEST_REPORTS_DIR"/{backend,frontend,e2e,performance,security}
    
    # Load test environment
    if [ -f "$TEST_ENV_FILE" ]; then
        export $(cat "$TEST_ENV_FILE" | grep -v '^#' | xargs)
    fi
    
    # Create test data directories
    mkdir -p test-data/{keys,backups,logs,performance}
    chmod -R 755 test-data/
}

# Start test services
start_test_services() {
    echo -e "${YELLOW}🐳 Starting test services with Docker Compose...${NC}"
    
    # Stop any existing test services
    docker-compose -f docker-compose.test.yml down --remove-orphans || true
    
    # Start test services
    docker-compose -f docker-compose.test.yml up -d postgres-test redis-test
    
    # Wait for services to be ready
    echo "Waiting for test services to be ready..."
    sleep 15
    
    # Verify services are running
    if ! docker-compose -f docker-compose.test.yml ps | grep -q "Up"; then
        echo -e "${RED}❌ Failed to start test services${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Test services are ready${NC}"
}

# Run backend unit tests
run_backend_unit_tests() {
    echo -e "${YELLOW}🔧 Running backend unit tests...${NC}"
    
    cd secure-api-key-storage
    
    # Install test dependencies
    pip install -q pytest pytest-cov pytest-asyncio pytest-html coverage-badge
    
    # Run unit tests with coverage
    python -m pytest tests/test_basic.py tests/test_security.py tests/test_rbac.py \
        -v \
        --cov=src \
        --cov-report=xml:../test-reports/backend/coverage.xml \
        --cov-report=html:../test-reports/backend/coverage-html \
        --cov-report=term-missing \
        --junit-xml=../test-reports/backend/unit-junit.xml \
        --html=../test-reports/backend/unit-report.html \
        --tb=short
    
    # Generate coverage badge
    coverage-badge -o ../test-reports/backend/coverage.svg -f || true
    
    cd "$PROJECT_ROOT"
    echo -e "${GREEN}✅ Backend unit tests completed${NC}"
}

# Run frontend unit tests
run_frontend_unit_tests() {
    echo -e "${YELLOW}⚛️ Running frontend unit tests...${NC}"
    
    cd secure-api-key-storage/dashboard/frontend
    
    # Install test dependencies if not already installed
    if [ ! -d "node_modules" ]; then
        echo "Installing frontend dependencies..."
        npm ci
    fi
    
    # Add missing test dependencies
    npm install -D @testing-library/react @testing-library/jest-dom @testing-library/user-event \
        @types/jest jest jest-environment-jsdom ts-jest || true
    
    # Run Jest tests with coverage
    npm run test:ci || npm test -- --coverage --watchAll=false --testResultsProcessor=jest-junit
    
    # Move coverage reports
    mkdir -p ../../../test-reports/frontend
    cp -r coverage/* ../../../test-reports/frontend/ || true
    
    cd "$PROJECT_ROOT"
    echo -e "${GREEN}✅ Frontend unit tests completed${NC}"
}

# Run integration tests
run_integration_tests() {
    echo -e "${YELLOW}🔗 Running integration tests...${NC}"
    
    cd secure-api-key-storage
    
    # Run integration tests
    python -m pytest tests/test_integration.py tests/test_security_integration.py \
        -v \
        --tb=short \
        --junit-xml=../test-reports/backend/integration-junit.xml \
        --html=../test-reports/backend/integration-report.html
    
    cd "$PROJECT_ROOT"
    echo -e "${GREEN}✅ Integration tests completed${NC}"
}

# Run performance tests
run_performance_tests() {
    echo -e "${YELLOW}⚡ Running performance regression tests...${NC}"
    
    cd secure-api-key-storage
    
    # Install performance test dependencies
    pip install -q psutil
    
    # Run performance tests
    python -m pytest tests/test_performance_regression.py tests/test_performance.py \
        -v \
        --tb=short \
        --junit-xml=../test-reports/performance/performance-junit.xml \
        --html=../test-reports/performance/performance-report.html
    
    cd "$PROJECT_ROOT"
    echo -e "${GREEN}✅ Performance tests completed${NC}"
}

# Run security tests
run_security_tests() {
    echo -e "${YELLOW}🔒 Running security regression tests...${NC}"
    
    cd secure-api-key-storage
    
    # Install security test dependencies
    pip install -q bandit safety
    
    # Run security-focused tests
    python -m pytest tests/test_critical_security_recommendations.py \
        -v \
        --tb=short \
        --junit-xml=../test-reports/security/security-junit.xml \
        --html=../test-reports/security/security-report.html
    
    # Run security scans
    echo "Running Bandit security scan..."
    bandit -r src/ -f json -o ../test-reports/security/bandit-report.json || true
    
    echo "Running Safety dependency check..."
    safety check --json --output ../test-reports/security/safety-report.json || true
    
    cd "$PROJECT_ROOT"
    echo -e "${GREEN}✅ Security tests completed${NC}"
}

# Run E2E tests (optional, requires GUI environment)
run_e2e_tests() {
    echo -e "${YELLOW}🌐 Running end-to-end tests...${NC}"
    
    # Check if Chrome is available
    if ! command -v google-chrome &> /dev/null && ! command -v chromium-browser &> /dev/null; then
        echo -e "${YELLOW}⚠️ Chrome not found, skipping E2E tests${NC}"
        return 0
    fi
    
    # Install Selenium
    pip install -q selenium
    
    # Start backend server
    cd secure-api-key-storage/dashboard/backend
    python main.py &
    BACKEND_PID=$!
    
    # Start frontend server
    cd ../frontend
    npm run build > /dev/null 2>&1
    npm start &
    FRONTEND_PID=$!
    
    # Wait for servers to start
    sleep 20
    
    # Run E2E tests
    cd ../../../
    python -m pytest secure-api-key-storage/tests/e2e/test_user_flows.py \
        -v \
        --tb=short \
        --junit-xml=test-reports/e2e/e2e-junit.xml \
        --html=test-reports/e2e/e2e-report.html || true
    
    # Cleanup
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    
    echo -e "${GREEN}✅ E2E tests completed${NC}"
}

# Generate test summary
generate_test_summary() {
    echo -e "${YELLOW}📊 Generating test summary...${NC}"
    
    SUMMARY_FILE="$TEST_REPORTS_DIR/test-summary.md"
    
    cat > "$SUMMARY_FILE" << EOF
# Test Execution Summary

Generated: $(date)

## Test Results Overview

### Backend Tests
- **Unit Tests**: $([ -f "$TEST_REPORTS_DIR/backend/unit-junit.xml" ] && echo "✅ PASSED" || echo "❌ FAILED")
- **Integration Tests**: $([ -f "$TEST_REPORTS_DIR/backend/integration-junit.xml" ] && echo "✅ PASSED" || echo "❌ FAILED")

### Frontend Tests
- **Unit Tests**: $([ -d "$TEST_REPORTS_DIR/frontend/coverage" ] && echo "✅ PASSED" || echo "❌ FAILED")

### Specialized Tests
- **Performance Tests**: $([ -f "$TEST_REPORTS_DIR/performance/performance-junit.xml" ] && echo "✅ PASSED" || echo "❌ FAILED")
- **Security Tests**: $([ -f "$TEST_REPORTS_DIR/security/security-junit.xml" ] && echo "✅ PASSED" || echo "❌ FAILED")
- **E2E Tests**: $([ -f "$TEST_REPORTS_DIR/e2e/e2e-junit.xml" ] && echo "✅ PASSED" || echo "❌ SKIPPED")

## Coverage Reports
- Backend Coverage: [HTML Report](backend/coverage-html/index.html)
- Frontend Coverage: [HTML Report](frontend/lcov-report/index.html)

## Detailed Reports
- Backend Unit Tests: [HTML Report](backend/unit-report.html)
- Integration Tests: [HTML Report](backend/integration-report.html)
- Performance Tests: [HTML Report](performance/performance-report.html)
- Security Tests: [HTML Report](security/security-report.html)
- E2E Tests: [HTML Report](e2e/e2e-report.html)

## Security Scan Results
- Bandit Security Scan: [JSON Report](security/bandit-report.json)
- Safety Dependency Check: [JSON Report](security/safety-report.json)

EOF

    echo -e "${GREEN}✅ Test summary generated: $SUMMARY_FILE${NC}"
}

# Cleanup function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up test environment...${NC}"
    
    # Stop test services
    docker-compose -f docker-compose.test.yml down --remove-orphans || true
    
    # Remove test environment file
    rm -f "$TEST_ENV_FILE"
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Main execution
main() {
    # Parse command line arguments
    RUN_E2E=false
    CLEANUP_ONLY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --e2e)
                RUN_E2E=true
                shift
                ;;
            --cleanup)
                CLEANUP_ONLY=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [--e2e] [--cleanup]"
                echo "  --e2e     Include E2E tests (requires GUI environment)"
                echo "  --cleanup Only cleanup test environment"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Cleanup and exit if requested
    if [ "$CLEANUP_ONLY" = true ]; then
        cleanup
        exit 0
    fi
    
    # Setup trap for cleanup on exit
    trap cleanup EXIT
    
    echo -e "${GREEN}🧪 Comprehensive Test Suite${NC}"
    echo "=============================="
    
    # Execute test phases
    create_test_env
    setup_test_env
    start_test_services
    
    # Run tests in order
    run_backend_unit_tests
    run_frontend_unit_tests
    run_integration_tests
    run_performance_tests
    run_security_tests
    
    if [ "$RUN_E2E" = true ]; then
        run_e2e_tests
    fi
    
    # Generate summary
    generate_test_summary
    
    echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
    echo -e "${YELLOW}📊 Test reports available in: $TEST_REPORTS_DIR${NC}"
    echo -e "${YELLOW}📋 Summary: $TEST_REPORTS_DIR/test-summary.md${NC}"
}

# Run main function
main "$@"