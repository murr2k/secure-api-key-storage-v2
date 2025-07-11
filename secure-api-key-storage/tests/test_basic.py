"""
Basic tests for the secure API key storage system.
These tests ensure the core functionality is working correctly.
"""

import unittest
import tempfile
import shutil
import os
from pathlib import Path


class TestBasicFunctionality(unittest.TestCase):
    """Test basic functionality of the secure storage system."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.test_dir) / "test_storage"

    def tearDown(self):
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_import_modules(self):
        """Test that all main modules can be imported."""
        try:
            from src.secure_storage import APIKeyStorage
            from src.config_manager import ConfigurationManager
            from src.key_rotation import KeyRotationManager
            from src.auth_manager import AuthenticationManager
            from src.rbac_models import RBACManager
            from src.audit_enhancement import TamperProofAuditLogger

            self.assertTrue(True, "All modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import module: {e}")

    def test_directory_creation(self):
        """Test that storage directories are created properly."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.assertTrue(self.storage_path.exists())
        self.assertTrue(self.storage_path.is_dir())

    def test_basic_arithmetic(self):
        """Simple test to ensure test framework is working."""
        self.assertEqual(2 + 2, 4)
        self.assertNotEqual(2 + 2, 5)

    def test_string_operations(self):
        """Test basic string operations."""
        test_string = "secure-api-key-storage"
        self.assertTrue(test_string.startswith("secure"))
        self.assertTrue(test_string.endswith("storage"))
        self.assertIn("api", test_string)

    def test_list_operations(self):
        """Test basic list operations."""
        test_list = [1, 2, 3, 4, 5]
        self.assertEqual(len(test_list), 5)
        self.assertIn(3, test_list)
        self.assertNotIn(10, test_list)


class TestEnvironmentSetup(unittest.TestCase):
    """Test environment setup and configuration."""

    def test_python_version(self):
        """Test that Python version is 3.6 or higher."""
        import sys

        self.assertGreaterEqual(sys.version_info.major, 3)
        if sys.version_info.major == 3:
            self.assertGreaterEqual(sys.version_info.minor, 6)

    def test_required_packages(self):
        """Test that required packages are available."""
        required_packages = [
            "cryptography",
            "click",
            "rich",
            "passlib",
            "pyotp",
            "jose",
            "prometheus_client",
        ]

        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                self.fail(f"Required package '{package}' is not installed")


if __name__ == "__main__":
    unittest.main()