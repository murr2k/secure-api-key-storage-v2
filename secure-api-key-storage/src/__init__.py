"""
Secure API Key Storage System

A production-ready secure storage system for API keys with AES-256-GCM encryption.
"""

from .secure_storage import APIKeyStorage
from .secure_storage_rbac import SecureStorageWithRBAC as SecureKeyStorageRBAC
from .config_manager import ConfigurationManager as ConfigManager
from .key_rotation import KeyRotationManager

__version__ = "1.0.0"
__author__ = "murr2k"
__all__ = ["APIKeyStorage", "SecureKeyStorageRBAC", "ConfigManager", "KeyRotationManager"]
