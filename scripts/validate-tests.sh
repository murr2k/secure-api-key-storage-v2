#!/bin/bash

# Test validation script
# Validates that all tests are properly configured and can run

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Validating test configuration...${NC}"

PROJECT_ROOT="$(pwd)"
BACKEND_DIR="secure-api-key-storage"
FRONTEND_DIR="secure-api-key-storage/dashboard/frontend"

# Check backend test configuration
validate_backend_tests() {
    echo -e "${YELLOW}🔧 Validating backend test configuration...${NC}"
    
    cd "$BACKEND_DIR"
    
    # Check if pytest.ini exists
    if [ ! -f "pytest.ini" ]; then
        echo -e "${RED}❌ pytest.ini not found${NC}"
        return 1
    fi
    
    # Check test files exist
    test_files=(
        "tests/test_basic.py"
        "tests/test_security.py" 
        "tests/test_rbac.py"
        "tests/test_integration.py"
        "tests/test_performance.py"
        "tests/test_performance_regression.py"
        "tests/test_critical_security_recommendations.py"
        "tests/test_security_integration.py"
        "tests/e2e/test_user_flows.py"
    )
    
    for test_file in "${test_files[@]}"; do
        if [ -f "$test_file" ]; then
            echo -e "${GREEN}✅ Found: $test_file${NC}"
        else
            echo -e "${RED}❌ Missing: $test_file${NC}"
        fi
    done
    
    # Check if test files are valid Python
    echo "Checking Python syntax..."
    for test_file in tests/*.py; do
        if [ -f "$test_file" ]; then
            python -m py_compile "$test_file" && echo -e "${GREEN}✅ Valid syntax: $test_file${NC}" || echo -e "${RED}❌ Syntax error: $test_file${NC}"
        fi
    done
    
    # Check dependencies
    echo "Checking test dependencies..."
    required_packages=(
        "pytest"
        "pytest-cov" 
        "pytest-asyncio"
        "pytest-html"
        "coverage"
        "bandit"
        "safety"
        "selenium"
        "psutil"
    )
    
    for package in "${required_packages[@]}"; do
        if pip show "$package" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Installed: $package${NC}"
        else
            echo -e "${YELLOW}⚠️ Missing: $package (will be installed during test run)${NC}"
        fi
    done
    
    cd "$PROJECT_ROOT"
}

# Check frontend test configuration
validate_frontend_tests() {
    echo -e "${YELLOW}⚛️ Validating frontend test configuration...${NC}"
    
    cd "$FRONTEND_DIR"
    
    # Check if Jest config exists
    if [ -f "jest.config.js" ]; then
        echo -e "${GREEN}✅ Found jest.config.js${NC}"
    else
        echo -e "${RED}❌ jest.config.js not found${NC}"
    fi
    
    if [ -f "jest.setup.js" ]; then
        echo -e "${GREEN}✅ Found jest.setup.js${NC}"
    else
        echo -e "${RED}❌ jest.setup.js not found${NC}"
    fi
    
    # Check test files exist
    test_files=(
        "__tests__/login.test.tsx"
        "__tests__/dashboard.test.tsx"
    )
    
    for test_file in "${test_files[@]}"; do
        if [ -f "$test_file" ]; then
            echo -e "${GREEN}✅ Found: $test_file${NC}"
        else
            echo -e "${RED}❌ Missing: $test_file${NC}"
        fi
    done
    
    # Check package.json has test scripts
    if grep -q '"test"' package.json; then
        echo -e "${GREEN}✅ Test scripts configured in package.json${NC}"
    else
        echo -e "${RED}❌ Test scripts missing in package.json${NC}"
    fi
    
    # Check if node_modules exists
    if [ -d "node_modules" ]; then
        echo -e "${GREEN}✅ Dependencies installed${NC}"
    else
        echo -e "${YELLOW}⚠️ Dependencies not installed (run npm install)${NC}"
    fi
    
    cd "$PROJECT_ROOT"
}

# Check Docker test configuration
validate_docker_tests() {
    echo -e "${YELLOW}🐳 Validating Docker test configuration...${NC}"
    
    # Check if docker-compose.test.yml exists
    if [ -f "docker-compose.test.yml" ]; then
        echo -e "${GREEN}✅ Found docker-compose.test.yml${NC}"
        
        # Validate docker-compose file
        if docker-compose -f docker-compose.test.yml config >/dev/null 2>&1; then
            echo -e "${GREEN}✅ Docker Compose configuration is valid${NC}"
        else
            echo -e "${RED}❌ Docker Compose configuration is invalid${NC}"
        fi
    else
        echo -e "${RED}❌ docker-compose.test.yml not found${NC}"
    fi
    
    # Check if Docker is running
    if docker info >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker is running${NC}"
    else
        echo -e "${YELLOW}⚠️ Docker is not running${NC}"
    fi
}

# Check GitHub Actions workflow
validate_github_actions() {
    echo -e "${YELLOW}🚀 Validating GitHub Actions workflow...${NC}"
    
    workflow_file=".github/workflows/deploy.yml"
    
    if [ -f "$workflow_file" ]; then
        echo -e "${GREEN}✅ Found GitHub Actions workflow${NC}"
        
        # Check for test jobs
        required_jobs=(
            "unit-tests"
            "integration-tests"
            "performance-tests"
            "security-regression-tests"
            "e2e-tests"
        )
        
        for job in "${required_jobs[@]}"; do
            if grep -q "$job:" "$workflow_file"; then
                echo -e "${GREEN}✅ Found job: $job${NC}"
            else
                echo -e "${RED}❌ Missing job: $job${NC}"
            fi
        done
        
        # Check for test services
        if grep -q "postgres:" "$workflow_file"; then
            echo -e "${GREEN}✅ PostgreSQL service configured${NC}"
        else
            echo -e "${YELLOW}⚠️ PostgreSQL service not configured${NC}"
        fi
        
        if grep -q "redis:" "$workflow_file"; then
            echo -e "${GREEN}✅ Redis service configured${NC}"
        else
            echo -e "${YELLOW}⚠️ Redis service not configured${NC}"
        fi
        
    else
        echo -e "${RED}❌ GitHub Actions workflow not found${NC}"
    fi
}

# Check test scripts
validate_test_scripts() {
    echo -e "${YELLOW}📜 Validating test scripts...${NC}"
    
    scripts=(
        "scripts/setup-test-env.sh"
        "scripts/run-all-tests.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [ -f "$script" ]; then
            echo -e "${GREEN}✅ Found: $script${NC}"
            if [ -x "$script" ]; then
                echo -e "${GREEN}✅ Executable: $script${NC}"
            else
                echo -e "${YELLOW}⚠️ Not executable: $script${NC}"
            fi
        else
            echo -e "${RED}❌ Missing: $script${NC}"
        fi
    done
}

# Run syntax check on test files
run_syntax_checks() {
    echo -e "${YELLOW}🔍 Running syntax checks...${NC}"
    
    # Python files
    echo "Checking Python test files..."
    find . -name "test_*.py" -path "*/tests/*" | while read -r file; do
        if python -m py_compile "$file" 2>/dev/null; then
            echo -e "${GREEN}✅ $file${NC}"
        else
            echo -e "${RED}❌ $file${NC}"
        fi
    done
    
    # TypeScript/JavaScript files
    if [ -d "$FRONTEND_DIR" ]; then
        echo "Checking frontend test files..."
        cd "$FRONTEND_DIR"
        if [ -d "node_modules" ]; then
            find . -name "*.test.tsx" -o -name "*.test.ts" | while read -r file; do
                if npx tsc --noEmit "$file" 2>/dev/null; then
                    echo -e "${GREEN}✅ $file${NC}"
                else
                    echo -e "${RED}❌ $file${NC}"
                fi
            done
        else
            echo -e "${YELLOW}⚠️ Frontend dependencies not installed, skipping syntax check${NC}"
        fi
        cd "$PROJECT_ROOT"
    fi
}

# Generate validation report
generate_validation_report() {
    echo -e "${YELLOW}📊 Generating validation report...${NC}"
    
    report_file="test-validation-report.md"
    
    cat > "$report_file" << EOF
# Test Configuration Validation Report

Generated: $(date)

## Summary

This report validates the test configuration for the secure API key storage project.

## Backend Tests
- Configuration files: pytest.ini
- Test discovery: tests/ directory
- Test types: unit, integration, performance, security, e2e

## Frontend Tests  
- Configuration files: jest.config.js, jest.setup.js
- Test framework: Jest with React Testing Library
- Test types: unit, component tests

## Docker Configuration
- Test environment: docker-compose.test.yml
- Services: PostgreSQL, Redis
- Isolation: Separate test database and cache

## CI/CD Integration
- GitHub Actions workflow: .github/workflows/deploy.yml
- Test stages: unit → integration → performance → security → e2e
- Artifacts: Coverage reports, test results, performance metrics

## Test Scripts
- Setup: scripts/setup-test-env.sh
- Runner: scripts/run-all-tests.sh
- Validation: scripts/validate-tests.sh

## Coverage Requirements
- Backend: 70% minimum coverage
- Frontend: 70% minimum coverage
- Security: 100% critical security tests

## Performance Thresholds
- Key operations: < 100ms
- Authentication: < 10ms
- Page load: < 5s
- API response: < 500ms

## Next Steps
1. Run validation: \`./scripts/validate-tests.sh\`
2. Setup environment: \`./scripts/setup-test-env.sh\`
3. Run all tests: \`./scripts/run-all-tests.sh\`
4. Check reports: \`test-reports/\`

EOF

    echo -e "${GREEN}✅ Validation report generated: $report_file${NC}"
}

# Main execution
main() {
    echo -e "${GREEN}🧪 Test Configuration Validator${NC}"
    echo "=================================="
    
    validate_backend_tests
    echo ""
    validate_frontend_tests
    echo ""
    validate_docker_tests
    echo ""
    validate_github_actions
    echo ""
    validate_test_scripts
    echo ""
    run_syntax_checks
    echo ""
    generate_validation_report
    
    echo -e "${GREEN}🎉 Validation completed!${NC}"
    echo -e "${YELLOW}📋 Check test-validation-report.md for details${NC}"
}

# Run main function
main "$@"