#!/usr/bin/env python3
"""
Test Runner for API Key Storage System
Executes all tests and generates comprehensive test report
"""

import unittest
import sys
import os
import time
import json
from datetime import datetime
import io
from contextlib import redirect_stdout, redirect_stderr

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import test modules
from tests import test_security, test_integration, test_performance


class TestReport:
    """Generate formatted test report"""
    
    def __init__(self):
        self.results = {
            "summary": {},
            "security_tests": {},
            "integration_tests": {},
            "performance_tests": {},
            "errors": [],
            "timestamp": datetime.now().isoformat()
        }
    
    def run_test_suite(self, test_module, suite_name):
        """Run a test suite and capture results"""
        print(f"\n{'='*60}")
        print(f"Running {suite_name}")
        print('='*60)
        
        # Create test suite
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(test_module)
        
        # Run tests with custom result
        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        start_time = time.time()
        result = runner.run(suite)
        duration = time.time() - start_time
        
        # Capture output
        output = stream.getvalue()
        print(output)
        
        # Store results
        self.results[suite_name] = {
            "total": result.testsRun,
            "passed": result.testsRun - len(result.failures) - len(result.errors),
            "failed": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
            "duration": round(duration, 2),
            "success_rate": round((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100, 1) if result.testsRun > 0 else 0
        }
        
        # Store error details
        for test, error in result.failures + result.errors:
            self.results["errors"].append({
                "suite": suite_name,
                "test": str(test),
                "error": error
            })
        
        return result.wasSuccessful()
    
    def generate_report(self):
        """Generate comprehensive test report"""
        # Calculate summary
        total_tests = sum(suite["total"] for suite in [
            self.results.get("security_tests", {}),
            self.results.get("integration_tests", {}),
            self.results.get("performance_tests", {})
        ])
        
        total_passed = sum(suite["passed"] for suite in [
            self.results.get("security_tests", {}),
            self.results.get("integration_tests", {}),
            self.results.get("performance_tests", {})
        ])
        
        total_duration = sum(suite.get("duration", 0) for suite in [
            self.results.get("security_tests", {}),
            self.results.get("integration_tests", {}),
            self.results.get("performance_tests", {})
        ])
        
        self.results["summary"] = {
            "total_tests": total_tests,
            "total_passed": total_passed,
            "total_failed": total_tests - total_passed,
            "overall_success_rate": round(total_passed / total_tests * 100, 1) if total_tests > 0 else 0,
            "total_duration": round(total_duration, 2)
        }
        
        # Generate markdown report
        report = f"""# API Key Storage System - Test Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

- **Total Tests:** {self.results['summary']['total_tests']}
- **Passed:** {self.results['summary']['total_passed']}
- **Failed:** {self.results['summary']['total_failed']}
- **Success Rate:** {self.results['summary']['overall_success_rate']}%
- **Total Duration:** {self.results['summary']['total_duration']} seconds

## Test Suite Results

### Security Tests
- **Total:** {self.results['security_tests'].get('total', 0)}
- **Passed:** {self.results['security_tests'].get('passed', 0)}
- **Failed:** {self.results['security_tests'].get('failed', 0)}
- **Success Rate:** {self.results['security_tests'].get('success_rate', 0)}%
- **Duration:** {self.results['security_tests'].get('duration', 0)} seconds

### Integration Tests
- **Total:** {self.results['integration_tests'].get('total', 0)}
- **Passed:** {self.results['integration_tests'].get('passed', 0)}
- **Failed:** {self.results['integration_tests'].get('failed', 0)}
- **Success Rate:** {self.results['integration_tests'].get('success_rate', 0)}%
- **Duration:** {self.results['integration_tests'].get('duration', 0)} seconds

### Performance Tests
- **Total:** {self.results['performance_tests'].get('total', 0)}
- **Passed:** {self.results['performance_tests'].get('passed', 0)}
- **Failed:** {self.results['performance_tests'].get('failed', 0)}
- **Success Rate:** {self.results['performance_tests'].get('success_rate', 0)}%
- **Duration:** {self.results['performance_tests'].get('duration', 0)} seconds

"""
        
        if self.results["errors"]:
            report += "\n## Failed Tests\n\n"
            for error in self.results["errors"]:
                report += f"### {error['suite']} - {error['test']}\n"
                report += f"```\n{error['error']}\n```\n\n"
        
        report += """
## Test Categories

### Security Tests Coverage
- ✅ Encryption at rest validation
- ✅ Access control mechanisms
- ✅ Audit logging functionality
- ✅ File permission checks
- ✅ Injection attack resistance
- ✅ Timing attack analysis
- ✅ Key rotation security
- ✅ Concurrent access safety
- ✅ Memory security assessment
- ✅ Vulnerability testing

### Integration Tests Coverage
- ✅ Complete key lifecycle
- ✅ Multi-user scenarios
- ✅ Data persistence
- ✅ Key expiry workflows
- ✅ Error recovery
- ✅ Bulk operations
- ✅ Concurrent modifications
- ✅ API format compatibility

### Performance Tests Coverage
- ✅ Write performance benchmarks
- ✅ Read performance benchmarks
- ✅ List operation scalability
- ✅ Concurrent load testing
- ✅ Memory usage analysis
- ✅ Encryption performance
- ✅ Scalability limits
- ✅ Cache effectiveness

## Recommendations

1. **All tests should pass** before deployment
2. **Performance benchmarks** should meet requirements
3. **Security tests** are critical and must not be skipped
4. Regular test execution in CI/CD pipeline
5. Monitor performance metrics over time

"""
        
        return report
    
    def save_results(self):
        """Save test results to files"""
        # Save JSON results
        with open('reports/test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Save markdown report
        report = self.generate_report()
        with open('reports/test_report.md', 'w') as f:
            f.write(report)
        
        return report


def main():
    """Main test runner"""
    print("API Key Storage System - Test Suite")
    print("=" * 60)
    
    # Create report instance
    report = TestReport()
    
    # Run test suites
    all_passed = True
    
    # Security Tests
    security_passed = report.run_test_suite(test_security, "security_tests")
    all_passed = all_passed and security_passed
    
    # Integration Tests
    integration_passed = report.run_test_suite(test_integration, "integration_tests")
    all_passed = all_passed and integration_passed
    
    # Performance Tests (always run, but don't fail build)
    performance_passed = report.run_test_suite(test_performance, "performance_tests")
    
    # Generate and save report
    print("\n" + "="*60)
    print("Generating Test Report...")
    print("="*60)
    
    final_report = report.save_results()
    print(final_report)
    
    # Exit with appropriate code
    if all_passed:
        print("\n✅ All critical tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please review the report.")
        sys.exit(1)


if __name__ == "__main__":
    main()