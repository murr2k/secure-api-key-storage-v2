"""
Integration Testing Utilities
Provides testing framework for API integrations
"""

import time
import json
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import logging
from dataclasses import dataclass
from enum import Enum

from base_integration import BaseIntegration, SecureKeyWrapper

logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Test execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TestResult:
    """Individual test result"""
    test_name: str
    status: TestStatus
    duration: float
    message: str = ""
    error: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'test_name': self.test_name,
            'status': self.status.value,
            'duration': self.duration,
            'message': self.message,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class IntegrationTestSuite:
    """Test suite for API integrations"""
    
    def __init__(self, integration: BaseIntegration):
        self.integration = integration
        self.results: List[TestResult] = []
        self.start_time = None
        self.end_time = None
    
    def run_all_tests(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Run all integration tests"""
        self.start_time = time.time()
        self.results = []
        
        # Basic tests
        self._test_api_key_validation(api_key)
        self._test_connection(api_key)
        self._test_authentication(api_key)
        self._test_configuration()
        
        # Service-specific tests
        self._run_service_specific_tests(api_key)
        
        self.end_time = time.time()
        return self._generate_report()
    
    def _test_api_key_validation(self, api_key: Optional[str] = None) -> None:
        """Test API key validation"""
        start = time.time()
        test_name = "API Key Validation"
        
        try:
            # Test with valid key
            key = api_key or self.integration.get_secure_key()
            if not key:
                self.results.append(TestResult(
                    test_name, TestStatus.SKIPPED, 0,
                    "No API key available for testing"
                ))
                return
            
            is_valid = self.integration.validate_api_key(key)
            if is_valid:
                self.results.append(TestResult(
                    test_name, TestStatus.PASSED, time.time() - start,
                    "API key format is valid"
                ))
            else:
                self.results.append(TestResult(
                    test_name, TestStatus.FAILED, time.time() - start,
                    "API key format is invalid"
                ))
            
            # Test with invalid key
            invalid_key = "invalid-key-format"
            if not self.integration.validate_api_key(invalid_key):
                logger.info(f"Invalid key correctly rejected for {self.integration.service_name}")
            
        except Exception as e:
            self.results.append(TestResult(
                test_name, TestStatus.FAILED, time.time() - start,
                error=str(e)
            ))
    
    def _test_connection(self, api_key: Optional[str] = None) -> None:
        """Test API connection"""
        start = time.time()
        test_name = "API Connection Test"
        
        try:
            key = api_key or self.integration.get_secure_key()
            if not key:
                self.results.append(TestResult(
                    test_name, TestStatus.SKIPPED, 0,
                    "No API key available for testing"
                ))
                return
            
            is_connected = self.integration.test_connection(key)
            if is_connected:
                self.results.append(TestResult(
                    test_name, TestStatus.PASSED, time.time() - start,
                    "Successfully connected to API"
                ))
            else:
                self.results.append(TestResult(
                    test_name, TestStatus.FAILED, time.time() - start,
                    "Failed to connect to API"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name, TestStatus.FAILED, time.time() - start,
                error=str(e)
            ))
    
    def _test_authentication(self, api_key: Optional[str] = None) -> None:
        """Test authentication headers"""
        start = time.time()
        test_name = "Authentication Headers"
        
        try:
            key = api_key or self.integration.get_secure_key()
            if not key:
                self.results.append(TestResult(
                    test_name, TestStatus.SKIPPED, 0,
                    "No API key available for testing"
                ))
                return
            
            headers = self.integration.get_headers(key)
            if headers and isinstance(headers, dict):
                self.results.append(TestResult(
                    test_name, TestStatus.PASSED, time.time() - start,
                    f"Headers generated: {list(headers.keys())}"
                ))
            else:
                self.results.append(TestResult(
                    test_name, TestStatus.FAILED, time.time() - start,
                    "Failed to generate authentication headers"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name, TestStatus.FAILED, time.time() - start,
                error=str(e)
            ))
    
    def _test_configuration(self) -> None:
        """Test configuration management"""
        start = time.time()
        test_name = "Configuration Management"
        
        try:
            # Test save and load config
            test_config = {'test_key': 'test_value', 'timestamp': datetime.now().isoformat()}
            self.integration.save_config(test_config)
            
            # Reload and verify
            self.integration._config = self.integration._load_config()
            if self.integration._config.get('test_key') == 'test_value':
                self.results.append(TestResult(
                    test_name, TestStatus.PASSED, time.time() - start,
                    "Configuration save/load working correctly"
                ))
            else:
                self.results.append(TestResult(
                    test_name, TestStatus.FAILED, time.time() - start,
                    "Configuration not properly saved/loaded"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name, TestStatus.FAILED, time.time() - start,
                error=str(e)
            ))
    
    def _run_service_specific_tests(self, api_key: Optional[str] = None) -> None:
        """Run service-specific tests based on integration type"""
        # This would be extended by specific integration test classes
        pass
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate test report"""
        total_tests = len(self.results)
        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
        
        return {
            'service': self.integration.service_name,
            'timestamp': datetime.now().isoformat(),
            'duration': self.end_time - self.start_time if self.end_time else 0,
            'summary': {
                'total': total_tests,
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'success_rate': (passed / total_tests * 100) if total_tests > 0 else 0
            },
            'results': [r.to_dict() for r in self.results]
        }
    
    def save_report(self, filepath: str) -> None:
        """Save test report to file"""
        report = self._generate_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Test report saved to {filepath}")
    
    def print_summary(self) -> None:
        """Print test summary to console"""
        report = self._generate_report()
        summary = report['summary']
        
        print(f"\n{'='*50}")
        print(f"Integration Test Results: {self.integration.service_name}")
        print(f"{'='*50}")
        print(f"Total Tests: {summary['total']}")
        print(f"Passed: {summary['passed']} ✓")
        print(f"Failed: {summary['failed']} ✗")
        print(f"Skipped: {summary['skipped']} -")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"Duration: {report['duration']:.2f}s")
        print(f"{'='*50}\n")
        
        # Print failed tests
        if summary['failed'] > 0:
            print("Failed Tests:")
            for result in self.results:
                if result.status == TestStatus.FAILED:
                    print(f"  ✗ {result.test_name}: {result.message or result.error}")
            print()


class GitHubTestSuite(IntegrationTestSuite):
    """GitHub-specific integration tests"""
    
    def _run_service_specific_tests(self, api_key: Optional[str] = None) -> None:
        """Run GitHub-specific tests"""
        # Import here to avoid circular import
        from github_integration import GitHubIntegration
        
        if not isinstance(self.integration, GitHubIntegration):
            return
        
        # Test user info retrieval
        self._test_get_user_info(api_key)
        # Test rate limit check
        self._test_rate_limit(api_key)
    
    def _test_get_user_info(self, api_key: Optional[str] = None) -> None:
        """Test GitHub user info retrieval"""
        start = time.time()
        test_name = "GitHub User Info"
        
        try:
            user_info = self.integration.get_user_info(api_key)
            if user_info and 'login' in user_info:
                self.results.append(TestResult(
                    test_name, TestStatus.PASSED, time.time() - start,
                    f"Retrieved user: {user_info['login']}"
                ))
            else:
                self.results.append(TestResult(
                    test_name, TestStatus.FAILED, time.time() - start,
                    "Failed to retrieve user information"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name, TestStatus.FAILED, time.time() - start,
                error=str(e)
            ))
    
    def _test_rate_limit(self, api_key: Optional[str] = None) -> None:
        """Test GitHub rate limit check"""
        start = time.time()
        test_name = "GitHub Rate Limit"
        
        try:
            rate_limit = self.integration.get_rate_limit(api_key)
            if rate_limit and 'rate' in rate_limit:
                remaining = rate_limit['rate'].get('remaining', 0)
                self.results.append(TestResult(
                    test_name, TestStatus.PASSED, time.time() - start,
                    f"Rate limit remaining: {remaining}"
                ))
            else:
                self.results.append(TestResult(
                    test_name, TestStatus.FAILED, time.time() - start,
                    "Failed to retrieve rate limit"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name, TestStatus.FAILED, time.time() - start,
                error=str(e)
            ))


class IntegrationTestRunner:
    """Runs tests for all registered integrations"""
    
    def __init__(self, wrapper: SecureKeyWrapper):
        self.wrapper = wrapper
        self.test_suites = {
            'github': GitHubTestSuite,
            'default': IntegrationTestSuite
        }
    
    def run_all_integrations(self) -> Dict[str, Dict[str, Any]]:
        """Run tests for all registered integrations"""
        results = {}
        
        for service_name, integration in self.wrapper._integrations.items():
            print(f"\nTesting {service_name}...")
            
            # Get appropriate test suite
            suite_class = self.test_suites.get(service_name, self.test_suites['default'])
            suite = suite_class(integration)
            
            # Run tests
            report = suite.run_all_tests()
            results[service_name] = report
            
            # Print summary
            suite.print_summary()
        
        return results
    
    def save_all_reports(self, output_dir: str = ".") -> None:
        """Save all test reports"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        results = self.run_all_integrations()
        
        # Save individual reports
        for service_name, report in results.items():
            filepath = os.path.join(output_dir, f"{service_name}_test_report.json")
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
        
        # Save combined report
        combined_report = {
            'timestamp': datetime.now().isoformat(),
            'services': results
        }
        
        filepath = os.path.join(output_dir, "integration_test_report.json")
        with open(filepath, 'w') as f:
            json.dump(combined_report, f, indent=2)
        
        logger.info(f"All test reports saved to {output_dir}")


# Utility functions for common test scenarios
def test_api_key_storage(integration: BaseIntegration, test_key: str) -> bool:
    """Test API key storage and retrieval"""
    try:
        # Store key
        if not integration.set_secure_key(test_key):
            logger.error("Failed to store API key")
            return False
        
        # Retrieve key
        retrieved_key = integration.get_secure_key()
        if retrieved_key != test_key:
            logger.error("Retrieved key doesn't match stored key")
            return False
        
        # Delete key
        if not integration.delete_secure_key():
            logger.error("Failed to delete API key")
            return False
        
        # Verify deletion
        if integration.get_secure_key() is not None:
            logger.error("Key still present after deletion")
            return False
        
        return True
    except Exception as e:
        logger.error(f"API key storage test failed: {e}")
        return False


def test_rate_limiting(integration: BaseIntegration, requests_per_second: int = 10) -> Dict[str, Any]:
    """Test API rate limiting behavior"""
    results = {
        'requests_sent': 0,
        'successful_requests': 0,
        'rate_limited_requests': 0,
        'errors': []
    }
    
    start_time = time.time()
    
    for i in range(requests_per_second):
        try:
            # Make a lightweight API call
            if integration.test_connection(integration.get_secure_key()):
                results['successful_requests'] += 1
            else:
                results['rate_limited_requests'] += 1
            results['requests_sent'] += 1
        except Exception as e:
            results['errors'].append(str(e))
        
        # Sleep to maintain desired rate
        elapsed = time.time() - start_time
        expected_elapsed = (i + 1) / requests_per_second
        if elapsed < expected_elapsed:
            time.sleep(expected_elapsed - elapsed)
    
    results['duration'] = time.time() - start_time
    results['actual_rate'] = results['requests_sent'] / results['duration']
    
    return results


# Example usage
def run_integration_tests_example():
    """Example of running integration tests"""
    from base_integration import SecureKeyWrapper
    from github_integration import create_github_integration
    from claude_integration import create_claude_integration
    
    # Create wrapper and register integrations
    wrapper = SecureKeyWrapper()
    wrapper.register_integration(create_github_integration())
    wrapper.register_integration(create_claude_integration())
    
    # Run tests
    runner = IntegrationTestRunner(wrapper)
    runner.save_all_reports("test_reports")
    
    return runner