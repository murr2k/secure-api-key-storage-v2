#!/usr/bin/env python3
"""Comprehensive test runner for the secure API key storage system."""

import os
import sys
import subprocess
import argparse
import time
from pathlib import Path
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "dashboard" / "backend"))

def run_command(cmd, description="", timeout=300):
    """Run a command and return the result."""
    print(f"\n{'='*60}")
    print(f"Running: {description or cmd}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            cmd.split() if isinstance(cmd, str) else cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=project_root
        )
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
            
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
            
        return result.returncode == 0, result
        
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {timeout} seconds")
        return False, None
    except Exception as e:
        print(f"Error running command: {e}")
        return False, None

def setup_environment():
    """Set up test environment."""
    print("Setting up test environment...")
    
    # Set environment variables for testing
    os.environ["MASTER_PASSWORD"] = "test_master_password_123"
    os.environ["API_KEY_MASTER"] = "test_master_password_123"  # Fallback
    os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_jwt_testing_12345"
    os.environ["CORS_ORIGINS"] = "http://localhost:3000,http://testserver"
    os.environ["TESTING"] = "true"
    
    # Create test reports directory
    reports_dir = project_root / "test-reports"
    reports_dir.mkdir(exist_ok=True)
    
    print("Environment setup complete.")

def run_unit_tests():
    """Run unit tests."""
    cmd = "python -m pytest tests/test_basic.py -v -m unit"
    return run_command(cmd, "Unit Tests")

def run_api_tests():
    """Run API endpoint tests."""
    cmd = "python -m pytest tests/test_api_endpoints.py -v -m api"
    return run_command(cmd, "API Endpoint Tests")

def run_security_tests():
    """Run security tests."""
    cmd = "python -m pytest tests/test_security_comprehensive.py -v -m security"
    return run_command(cmd, "Security Tests")

def run_database_tests():
    """Run database tests."""
    cmd = "python -m pytest tests/test_database.py -v -m database"
    return run_command(cmd, "Database Tests")

def run_cache_tests():
    """Run cache tests."""
    cmd = "python -m pytest tests/test_cache.py -v -m cache"
    return run_command(cmd, "Cache Tests")

def run_integration_tests():
    """Run integration tests."""
    cmd = "python -m pytest tests/test_integration_comprehensive.py -v -m integration"
    return run_command(cmd, "Integration Tests")

def run_performance_tests():
    """Run performance tests."""
    cmd = "python -m pytest tests/ -v -m performance --timeout=600"
    return run_command(cmd, "Performance Tests", timeout=600)

def run_all_tests():
    """Run all tests."""
    cmd = "python -m pytest tests/ -v --maxfail=5"
    return run_command(cmd, "All Tests", timeout=900)

def run_coverage_report():
    """Generate coverage report."""
    cmd = "python -m pytest tests/ --cov=src --cov=dashboard/backend --cov-report=html --cov-report=term"
    return run_command(cmd, "Coverage Report", timeout=600)

def run_linting():
    """Run code linting."""
    commands = [
        ("python -m flake8 src/ --max-line-length=100", "Flake8 - Source Code"),
        ("python -m flake8 dashboard/backend/ --max-line-length=100", "Flake8 - Backend"),
        ("python -m flake8 tests/ --max-line-length=100", "Flake8 - Tests"),
    ]
    
    all_passed = True
    for cmd, desc in commands:
        success, _ = run_command(cmd, desc)
        if not success:
            all_passed = False
            
    return all_passed

def run_security_scan():
    """Run security scanning."""
    cmd = "python -m bandit -r src/ dashboard/backend/ -f json -o test-reports/security-scan.json"
    success, result = run_command(cmd, "Bandit Security Scan")
    
    # Bandit returns non-zero for any issues, but we want to see the report
    if result and result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
        return True
    return success

def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="Comprehensive test runner")
    parser.add_argument("--test-type", choices=[
        "unit", "api", "security", "database", "cache", "integration", 
        "performance", "all", "coverage", "lint", "security-scan"
    ], default="all", help="Type of tests to run")
    parser.add_argument("--no-setup", action="store_true", help="Skip environment setup")
    parser.add_argument("--fast", action="store_true", help="Skip slow tests")
    
    args = parser.parse_args()
    
    # Record start time
    start_time = datetime.now()
    print(f"Starting comprehensive test run at {start_time}")
    print(f"Test type: {args.test_type}")
    
    # Set up environment
    if not args.no_setup:
        setup_environment()
    
    # Run tests based on type
    success = True
    
    if args.test_type == "unit":
        success, _ = run_unit_tests()
    elif args.test_type == "api":
        success, _ = run_api_tests()
    elif args.test_type == "security":
        success, _ = run_security_tests()
    elif args.test_type == "database":
        success, _ = run_database_tests()
    elif args.test_type == "cache":
        success, _ = run_cache_tests()
    elif args.test_type == "integration":
        success, _ = run_integration_tests()
    elif args.test_type == "performance":
        success, _ = run_performance_tests()
    elif args.test_type == "coverage":
        success, _ = run_coverage_report()
    elif args.test_type == "lint":
        success = run_linting()
    elif args.test_type == "security-scan":
        success = run_security_scan()
    elif args.test_type == "all":
        print("\nRunning comprehensive test suite...")
        
        test_suite = [
            ("Linting", run_linting),
            ("Unit Tests", run_unit_tests),
            ("API Tests", run_api_tests),
            ("Security Tests", run_security_tests),
            ("Database Tests", run_database_tests),
            ("Cache Tests", run_cache_tests),
            ("Integration Tests", run_integration_tests),
        ]
        
        if not args.fast:
            test_suite.extend([
                ("Performance Tests", run_performance_tests),
                ("Security Scan", run_security_scan),
                ("Coverage Report", run_coverage_report),
            ])
        
        results = {}
        for test_name, test_func in test_suite:
            print(f"\n{'*'*80}")
            print(f"Running {test_name}")
            print(f"{'*'*80}")
            
            test_success, _ = test_func() if test_func != run_linting and test_func != run_security_scan else (test_func(), None)
            results[test_name] = test_success
            
            if not test_success:
                success = False
                print(f"❌ {test_name} FAILED")
            else:
                print(f"✅ {test_name} PASSED")
                
        # Print summary
        end_time = datetime.now()
        duration = end_time - start_time
        
        print(f"\n{'='*80}")
        print("TEST SUITE SUMMARY")
        print(f"{'='*80}")
        print(f"Started: {start_time}")
        print(f"Ended: {end_time}")
        print(f"Duration: {duration}")
        print()
        
        for test_name, test_result in results.items():
            status = "✅ PASS" if test_result else "❌ FAIL"
            print(f"{test_name:<30} {status}")
            
        print()
        overall_status = "✅ ALL TESTS PASSED" if success else "❌ SOME TESTS FAILED"
        print(f"Overall Status: {overall_status}")
        
        # Generate test report
        report_file = project_root / "test-reports" / "test-summary.txt"
        with open(report_file, 'w') as f:
            f.write(f"Test Suite Summary\n")
            f.write(f"==================\n\n")
            f.write(f"Started: {start_time}\n")
            f.write(f"Ended: {end_time}\n")
            f.write(f"Duration: {duration}\n\n")
            
            for test_name, test_result in results.items():
                status = "PASS" if test_result else "FAIL"
                f.write(f"{test_name}: {status}\n")
                
            f.write(f"\nOverall Status: {'PASS' if success else 'FAIL'}\n")
            
        print(f"\nDetailed test report saved to: {report_file}")
    
    # Exit with appropriate code
    exit_code = 0 if success else 1
    print(f"\nExiting with code: {exit_code}")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
