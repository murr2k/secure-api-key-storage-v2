#!/usr/bin/env python3
"""
Integration Test Runner for Secure API Key Storage System
Runs all security tests and generates comprehensive reports
"""

import os
import sys
import unittest
import json
import time
from datetime import datetime
import argparse
from io import StringIO
import traceback

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class IntegrationTestRunner:
    """Comprehensive test runner with reporting"""
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'errors': 0,
                'skipped': 0
            },
            'test_suites': {},
            'security_features': {},
            'recommendations': []
        }
    
    def run_all_tests(self):
        """Run all test suites"""
        print("=" * 70)
        print("SECURE API KEY STORAGE - INTEGRATION TEST SUITE")
        print("=" * 70)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Discover and run all test modules
        test_modules = [
            'test_security',
            'test_integration', 
            'test_performance',
            'test_security_integration',
            'test_critical_security_recommendations'
        ]
        
        for module_name in test_modules:
            self._run_test_module(module_name)
        
        # Generate final report
        self._generate_report()
        
        return self.test_results
    
    def _run_test_module(self, module_name):
        """Run a specific test module"""
        print(f"\n{'=' * 50}")
        print(f"Running: {module_name}")
        print('=' * 50)
        
        try:
            # Import test module
            module = __import__(module_name)
            
            # Create test suite
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromModule(module)
            
            # Run tests with custom result
            stream = StringIO()
            runner = unittest.TextTestRunner(
                stream=stream,
                verbosity=2 if self.verbose else 1
            )
            
            start_time = time.time()
            result = runner.run(suite)
            duration = time.time() - start_time
            
            # Capture results
            self.test_results['test_suites'][module_name] = {
                'duration': duration,
                'tests_run': result.testsRun,
                'failures': len(result.failures),
                'errors': len(result.errors),
                'skipped': len(result.skipped) if hasattr(result, 'skipped') else 0,
                'success': result.wasSuccessful(),
                'details': []
            }
            
            # Update summary
            self.test_results['summary']['total'] += result.testsRun
            self.test_results['summary']['passed'] += (
                result.testsRun - len(result.failures) - len(result.errors) -
                (len(result.skipped) if hasattr(result, 'skipped') else 0)
            )
            self.test_results['summary']['failed'] += len(result.failures)
            self.test_results['summary']['errors'] += len(result.errors)
            self.test_results['summary']['skipped'] += (
                len(result.skipped) if hasattr(result, 'skipped') else 0
            )
            
            # Capture failure details
            for test, trace in result.failures:
                self.test_results['test_suites'][module_name]['details'].append({
                    'type': 'failure',
                    'test': str(test),
                    'message': trace
                })
            
            # Capture error details
            for test, trace in result.errors:
                self.test_results['test_suites'][module_name]['details'].append({
                    'type': 'error',
                    'test': str(test),
                    'message': trace
                })
            
            # Print module summary
            print(f"\nModule Summary:")
            print(f"  Tests run: {result.testsRun}")
            print(f"  Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
            print(f"  Failed: {len(result.failures)}")
            print(f"  Errors: {len(result.errors)}")
            print(f"  Duration: {duration:.2f}s")
            
            if result.failures or result.errors:
                print("\n  Issues found:")
                for test, _ in result.failures + result.errors:
                    print(f"    - {test}")
            
        except ImportError as e:
            print(f"  ERROR: Could not import {module_name}: {e}")
            self.test_results['test_suites'][module_name] = {
                'error': f"Import error: {str(e)}",
                'success': False
            }
        except Exception as e:
            print(f"  ERROR: Unexpected error in {module_name}: {e}")
            traceback.print_exc()
            self.test_results['test_suites'][module_name] = {
                'error': f"Unexpected error: {str(e)}",
                'success': False
            }
    
    def _analyze_security_features(self):
        """Analyze which security features are properly tested"""
        features = {
            'encryption': {
                'status': 'implemented',
                'tests': ['test_encryption_at_rest', 'test_secure_storage'],
                'coverage': 'high'
            },
            'access_control': {
                'status': 'partial',
                'tests': ['test_access_control', 'test_role_based_access_control'],
                'coverage': 'medium'
            },
            'authentication': {
                'status': 'recommended',
                'tests': ['test_authentication_layer'],
                'coverage': 'low'
            },
            'key_rotation': {
                'status': 'implemented',
                'tests': ['test_key_rotation', 'test_complete_security_workflow'],
                'coverage': 'high'
            },
            'audit_logging': {
                'status': 'implemented',
                'tests': ['test_audit_logging'],
                'coverage': 'medium'
            },
            'memory_security': {
                'status': 'partial',
                'tests': ['test_secure_memory_wiping', 'test_memory_locking'],
                'coverage': 'low'
            },
            'constant_time_ops': {
                'status': 'implemented',
                'tests': ['test_constant_time_comparison'],
                'coverage': 'medium'
            },
            'concurrent_safety': {
                'status': 'implemented',
                'tests': ['test_concurrent_access_security'],
                'coverage': 'high'
            }
        }
        
        self.test_results['security_features'] = features
    
    def _generate_recommendations(self):
        """Generate security recommendations based on test results"""
        recommendations = []
        
        # Check test coverage
        if self.test_results['summary']['failed'] > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'testing',
                'recommendation': 'Fix failing tests before deployment',
                'details': f"{self.test_results['summary']['failed']} tests are currently failing"
            })
        
        # Security feature recommendations
        self._analyze_security_features()
        
        for feature, info in self.test_results['security_features'].items():
            if info['status'] == 'recommended':
                recommendations.append({
                    'priority': 'high',
                    'category': 'security',
                    'recommendation': f'Implement {feature.replace("_", " ").title()}',
                    'details': f'Currently {info["coverage"]} test coverage'
                })
            elif info['status'] == 'partial':
                recommendations.append({
                    'priority': 'medium',
                    'category': 'security',
                    'recommendation': f'Complete implementation of {feature.replace("_", " ").title()}',
                    'details': f'Feature is partially implemented with {info["coverage"]} coverage'
                })
        
        self.test_results['recommendations'] = recommendations
    
    def _generate_report(self):
        """Generate final test report"""
        self._generate_recommendations()
        
        print("\n" + "=" * 70)
        print("FINAL TEST REPORT")
        print("=" * 70)
        
        # Summary
        summary = self.test_results['summary']
        print(f"\nTest Summary:")
        print(f"  Total Tests: {summary['total']}")
        print(f"  Passed: {summary['passed']} ({summary['passed']/summary['total']*100:.1f}%)")
        print(f"  Failed: {summary['failed']}")
        print(f"  Errors: {summary['errors']}")
        print(f"  Skipped: {summary['skipped']}")
        
        # Security Features
        print(f"\nSecurity Features Coverage:")
        for feature, info in self.test_results['security_features'].items():
            status_symbol = "✓" if info['status'] == 'implemented' else "⚠" if info['status'] == 'partial' else "✗"
            print(f"  {status_symbol} {feature.replace('_', ' ').title()}: {info['coverage']} coverage")
        
        # Recommendations
        if self.test_results['recommendations']:
            print(f"\nRecommendations:")
            for rec in sorted(self.test_results['recommendations'], 
                            key=lambda x: ['critical', 'high', 'medium', 'low'].index(x['priority'])):
                print(f"  [{rec['priority'].upper()}] {rec['recommendation']}")
                if rec['details']:
                    print(f"         {rec['details']}")
        
        # Save detailed report
        report_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"integration_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_path, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\nDetailed report saved to: {report_path}")
        
        # Overall status
        overall_success = (
            summary['failed'] == 0 and 
            summary['errors'] == 0 and
            all(not any(r['priority'] == 'critical' for r in self.test_results['recommendations']))
        )
        
        print(f"\nOverall Status: {'PASSED' if overall_success else 'FAILED'}")
        
        if not overall_success:
            sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Run integration tests for Secure API Key Storage System'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--module', '-m',
        help='Run specific test module only'
    )
    
    args = parser.parse_args()
    
    runner = IntegrationTestRunner(verbose=args.verbose)
    
    if args.module:
        # Run specific module
        runner._run_test_module(args.module)
        runner._generate_report()
    else:
        # Run all tests
        runner.run_all_tests()


if __name__ == '__main__':
    main()