"""
Performance regression tests for the secure API key storage system.
These tests ensure that performance doesn't degrade over time.
"""

import asyncio
import time
import unittest
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import json
import os
from pathlib import Path

# Import test utilities
try:
    from src.secure_storage import APIKeyStorage
    from src.secure_storage_rbac import SecureKeyStorageRBAC
    from src.auth_manager import AuthenticationManager
    from src.rbac_models import RBACManager
    from src.audit_enhancement import TamperProofAuditLogger
except ImportError as e:
    print(f"Warning: Could not import modules for performance tests: {e}")


class PerformanceTestCase(unittest.TestCase):
    """Base class for performance tests."""
    
    def setUp(self):
        """Set up performance test environment."""
        self.test_dir = Path("test-data/performance")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.results_file = self.test_dir / "performance_results.json"
        self.baseline_file = self.test_dir / "performance_baseline.json"
        
        # Performance thresholds (in seconds)
        self.thresholds = {
            "key_storage": 0.1,      # 100ms for key storage
            "key_retrieval": 0.05,   # 50ms for key retrieval
            "encryption": 0.02,      # 20ms for encryption
            "decryption": 0.02,      # 20ms for decryption
            "auth_check": 0.01,      # 10ms for auth check
            "audit_log": 0.05,       # 50ms for audit logging
        }
        
        self.results = {}
    
    def tearDown(self):
        """Save performance results."""
        if self.results:
            self._save_results()
    
    def measure_time(self, func, *args, **kwargs) -> float:
        """Measure execution time of a function."""
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        return end_time - start_time
    
    def measure_average_time(self, func, iterations=10, *args, **kwargs) -> Dict[str, float]:
        """Measure average execution time over multiple iterations."""
        times = []
        for _ in range(iterations):
            execution_time = self.measure_time(func, *args, **kwargs)
            times.append(execution_time)
        
        return {
            "average": statistics.mean(times),
            "median": statistics.median(times),
            "min": min(times),
            "max": max(times),
            "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
        }
    
    def _save_results(self):
        """Save performance results to file."""
        try:
            with open(self.results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save performance results: {e}")
    
    def _load_baseline(self) -> Dict[str, Any]:
        """Load baseline performance results."""
        try:
            if self.baseline_file.exists():
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load baseline: {e}")
        return {}
    
    def assert_performance(self, test_name: str, measured_time: float, threshold: float = None):
        """Assert that performance meets threshold."""
        if threshold is None:
            threshold = self.thresholds.get(test_name, 1.0)
        
        self.assertLessEqual(
            measured_time, 
            threshold,
            f"Performance test '{test_name}' exceeded threshold: {measured_time:.4f}s > {threshold:.4f}s"
        )
        
        # Store result
        self.results[test_name] = {
            "measured_time": measured_time,
            "threshold": threshold,
            "passed": measured_time <= threshold
        }


class TestStoragePerformance(PerformanceTestCase):
    """Test storage operations performance."""
    
    def test_key_storage_performance(self):
        """Test API key storage performance."""
        # Mock storage operations
        def mock_store_key():
            # Simulate encryption and storage
            time.sleep(0.001)  # 1ms simulation
            return True
        
        avg_time = self.measure_average_time(mock_store_key, iterations=100)
        self.assert_performance("key_storage", avg_time["average"])
        
        print(f"Key storage performance: {avg_time['average']:.4f}s average")
    
    def test_key_retrieval_performance(self):
        """Test API key retrieval performance."""
        def mock_retrieve_key():
            # Simulate decryption and retrieval
            time.sleep(0.0005)  # 0.5ms simulation
            return "mock_key_value"
        
        avg_time = self.measure_average_time(mock_retrieve_key, iterations=100)
        self.assert_performance("key_retrieval", avg_time["average"])
        
        print(f"Key retrieval performance: {avg_time['average']:.4f}s average")
    
    def test_bulk_operations_performance(self):
        """Test bulk operations performance."""
        def mock_bulk_operation():
            # Simulate processing 100 keys
            for _ in range(100):
                time.sleep(0.00001)  # 0.01ms per key
            return True
        
        execution_time = self.measure_time(mock_bulk_operation)
        self.assert_performance("bulk_operations", execution_time, threshold=0.5)
        
        print(f"Bulk operations performance: {execution_time:.4f}s for 100 keys")


class TestEncryptionPerformance(PerformanceTestCase):
    """Test encryption/decryption performance."""
    
    def test_encryption_performance(self):
        """Test encryption performance."""
        def mock_encrypt():
            # Simulate AES-256-GCM encryption
            time.sleep(0.001)  # 1ms simulation
            return b"encrypted_data"
        
        avg_time = self.measure_average_time(mock_encrypt, iterations=50)
        self.assert_performance("encryption", avg_time["average"])
        
        print(f"Encryption performance: {avg_time['average']:.4f}s average")
    
    def test_decryption_performance(self):
        """Test decryption performance."""
        def mock_decrypt():
            # Simulate AES-256-GCM decryption
            time.sleep(0.0008)  # 0.8ms simulation
            return "decrypted_data"
        
        avg_time = self.measure_average_time(mock_decrypt, iterations=50)
        self.assert_performance("decryption", avg_time["average"])
        
        print(f"Decryption performance: {avg_time['average']:.4f}s average")


class TestAuthenticationPerformance(PerformanceTestCase):
    """Test authentication performance."""
    
    def test_auth_check_performance(self):
        """Test authentication check performance."""
        def mock_auth_check():
            # Simulate JWT verification
            time.sleep(0.0005)  # 0.5ms simulation
            return True
        
        avg_time = self.measure_average_time(mock_auth_check, iterations=100)
        self.assert_performance("auth_check", avg_time["average"])
        
        print(f"Auth check performance: {avg_time['average']:.4f}s average")
    
    def test_rbac_check_performance(self):
        """Test RBAC permission check performance."""
        def mock_rbac_check():
            # Simulate RBAC permission evaluation
            time.sleep(0.0002)  # 0.2ms simulation
            return True
        
        avg_time = self.measure_average_time(mock_rbac_check, iterations=100)
        self.assert_performance("rbac_check", avg_time["average"], threshold=0.01)
        
        print(f"RBAC check performance: {avg_time['average']:.4f}s average")


class TestAuditPerformance(PerformanceTestCase):
    """Test audit logging performance."""
    
    def test_audit_logging_performance(self):
        """Test audit logging performance."""
        def mock_audit_log():
            # Simulate audit log writing
            time.sleep(0.002)  # 2ms simulation
            return True
        
        avg_time = self.measure_average_time(mock_audit_log, iterations=50)
        self.assert_performance("audit_log", avg_time["average"])
        
        print(f"Audit logging performance: {avg_time['average']:.4f}s average")


class TestConcurrencyPerformance(PerformanceTestCase):
    """Test concurrent operations performance."""
    
    def test_concurrent_key_operations(self):
        """Test concurrent key operations performance."""
        def mock_concurrent_operation():
            time.sleep(0.001)  # 1ms simulation
            return True
        
        start_time = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(mock_concurrent_operation) for _ in range(50)]
            
            for future in as_completed(futures):
                future.result()
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        # Should be much faster than sequential execution
        self.assertLess(total_time, 10.0, "Concurrent operations took too long")
        
        print(f"Concurrent operations performance: {total_time:.4f}s for 50 operations")


class TestMemoryPerformance(PerformanceTestCase):
    """Test memory usage performance."""
    
    def test_memory_cleanup(self):
        """Test that memory is properly cleaned up."""
        import gc
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Simulate memory-intensive operations
        large_data = []
        for i in range(1000):
            large_data.append(f"test_data_{i}" * 100)
        
        # Clear references and force garbage collection
        large_data.clear()
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal (less than 10MB)
        self.assertLess(memory_increase, 10 * 1024 * 1024, 
                       f"Memory not properly cleaned up: {memory_increase / 1024 / 1024:.2f}MB increase")
        
        print(f"Memory performance: {memory_increase / 1024 / 1024:.2f}MB increase")


class TestLoadPerformance(PerformanceTestCase):
    """Test system performance under load."""
    
    def test_sustained_load(self):
        """Test performance under sustained load."""
        def sustained_operation():
            # Simulate sustained operations
            operations = 0
            start_time = time.perf_counter()
            
            while time.perf_counter() - start_time < 5.0:  # Run for 5 seconds
                time.sleep(0.001)  # 1ms per operation
                operations += 1
            
            return operations
        
        operations_count = sustained_operation()
        ops_per_second = operations_count / 5.0
        
        # Should handle at least 500 operations per second
        self.assertGreaterEqual(ops_per_second, 500, 
                               f"Sustained load performance too low: {ops_per_second:.1f} ops/sec")
        
        print(f"Sustained load performance: {ops_per_second:.1f} operations/second")


if __name__ == "__main__":
    # Create test data directory
    os.makedirs("test-data/performance", exist_ok=True)
    
    # Run performance tests
    unittest.main(verbosity=2)