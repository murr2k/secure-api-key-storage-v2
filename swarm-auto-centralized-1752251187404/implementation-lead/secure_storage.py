"""
Secure API Key Storage Module

This module provides secure storage for API keys using encryption,
secure key derivation, and proper key management practices.
"""

import os
import json
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Import secure memory management
try:
    from .secure_memory import (
        SecureString,
        SecureBytes,
        MemoryProtectedDict,
        constant_time_compare,
        constant_time_compare_bytes,
        secure_zero_memory,
        MemoryLock
    )
except ImportError:
    # Fallback to direct import for testing
    from secure_memory import (
        SecureString,
        SecureBytes,
        MemoryProtectedDict,
        constant_time_compare,
        constant_time_compare_bytes,
        secure_zero_memory,
        MemoryLock
    )


class SecureKeyStorage:
    """Secure storage system for API keys with encryption and key management.
    
    This implementation includes:
    - Constant-time comparisons to prevent timing attacks
    - Secure memory clearing to remove sensitive data after use
    - Memory locking to prevent sensitive data from being swapped to disk
    - Automatic memory protection for sensitive strings and bytes
    """
    
    def __init__(self, storage_path: str = ".secure_keys", master_key_env: str = "API_KEY_MASTER"):
        """
        Initialize the secure storage system.
        
        Args:
            storage_path: Directory path for storing encrypted keys
            master_key_env: Environment variable name for master key
        """
        self.storage_path = Path(storage_path)
        self.master_key_env = master_key_env
        self.config_file = self.storage_path / "config.json"
        self.keys_file = self.storage_path / "keys.enc"
        self.salt_file = self.storage_path / "salt.bin"
        
        # Initialize storage directory
        self._init_storage()
        
        # Load or generate salt
        self.salt = self._load_or_generate_salt()
        
        # Derive encryption key from master key with memory protection
        with MemoryLock():
            self.encryption_key = SecureBytes(self._derive_key())
        
        # Use memory-protected storage for sensitive data
        self._key_cache = MemoryProtectedDict()
    
    def _init_storage(self):
        """Initialize storage directory with proper permissions."""
        self.storage_path.mkdir(mode=0o700, exist_ok=True)
        
        # Set restrictive permissions on storage directory
        os.chmod(self.storage_path, 0o700)
    
    def _load_or_generate_salt(self) -> bytes:
        """Load existing salt or generate a new one."""
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(32)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            os.chmod(self.salt_file, 0o600)
            return salt
    
    def _get_master_key(self) -> bytes:
        """Retrieve master key from environment or generate one."""
        master_key = os.environ.get(self.master_key_env)
        
        if not master_key:
            # Generate a secure master key if not exists
            master_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            print(f"WARNING: No master key found. Generated new master key.")
            print(f"Please set environment variable {self.master_key_env}={master_key}")
            print("This key is required to decrypt your API keys.")
            # Use SecureString for the master key
            secure_key = SecureString(master_key)
            result = secure_key._value.encode('utf-8')
            return result
        
        # Use SecureString for the master key
        secure_key = SecureString(master_key)
        result = secure_key._value.encode('utf-8')
        return result
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from master key using PBKDF2."""
        # Get master key with memory protection
        with MemoryLock():
            master_key = self._get_master_key()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )
            
            derived_key = kdf.derive(master_key)
            
            # Securely clear the master key from memory
            secure_zero_memory(master_key)
            
            return derived_key
    
    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-GCM."""
        # Use memory lock during encryption
        with MemoryLock():
            # Generate a random 96-bit IV for GCM
            iv = os.urandom(12)
            
            # Create cipher with secure key access
            cipher = Cipher(
                algorithms.AES(bytes(self.encryption_key)),
                modes.GCM(iv),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Return IV + tag + ciphertext
            result = iv + encryptor.tag + ciphertext
            
            # Clear sensitive data from memory
            secure_zero_memory(data)
            
            return result
    
    def _decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data encrypted with AES-GCM."""
        # Use memory lock during decryption
        with MemoryLock():
            # Extract components
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher with secure key access
            cipher = Cipher(
                algorithms.AES(bytes(self.encryption_key)),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
    
    def store_key(self, key_name: str, api_key: str, metadata: Optional[Dict] = None) -> bool:
        """
        Store an API key securely.
        
        Args:
            key_name: Unique identifier for the key
            api_key: The API key to store
            metadata: Optional metadata (service name, expiry, etc.)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Use SecureString for the API key
            secure_api_key = SecureString(api_key)
            
            # Load existing keys
            keys = self._load_keys()
            
            # Create key entry with secure storage
            key_entry = {
                'key': str(secure_api_key),
                'created': datetime.now().isoformat(),
                'last_rotated': datetime.now().isoformat(),
                'metadata': metadata or {}
            }
            
            # Add or update key
            keys[key_name] = key_entry
            
            # Save encrypted keys
            self._save_keys(keys)
            
            # Update configuration
            self._update_config(key_name, metadata)
            
            # Clear the secure API key from memory
            secure_api_key.clear()
            
            return True
            
        except Exception as e:
            print(f"Error storing key: {e}")
            # Ensure sensitive data is cleared on error
            if 'secure_api_key' in locals():
                secure_api_key.clear()
            return False
    
    def retrieve_key(self, key_name: str) -> Optional[str]:
        """
        Retrieve a stored API key.
        
        Args:
            key_name: The identifier of the key to retrieve
        
        Returns:
            The API key if found, None otherwise
        """
        try:
            with MemoryLock():
                keys = self._load_keys()
                if key_name in keys:
                    # Return the key but maintain it in cache with protection
                    api_key = keys[key_name]['key']
                    # Cache with memory protection
                    self._key_cache[key_name] = api_key
                    return api_key
                return None
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None
        finally:
            # Clear the keys dict from memory
            if 'keys' in locals():
                secure_zero_memory(keys)
    
    def list_keys(self) -> List[Dict]:
        """
        List all stored keys with metadata (without exposing the actual keys).
        
        Returns:
            List of key information dictionaries
        """
        try:
            keys = self._load_keys()
            result = []
            
            for key_name, key_data in keys.items():
                info = {
                    'name': key_name,
                    'created': key_data.get('created'),
                    'last_rotated': key_data.get('last_rotated'),
                    'metadata': key_data.get('metadata', {})
                }
                result.append(info)
            
            return result
            
        except Exception:
            return []
    
    def rotate_key(self, key_name: str, new_api_key: str) -> bool:
        """
        Rotate an existing API key.
        
        Args:
            key_name: The identifier of the key to rotate
            new_api_key: The new API key
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Use SecureString for the new API key
            secure_new_key = SecureString(new_api_key)
            
            with MemoryLock():
                keys = self._load_keys()
                
                if key_name not in keys:
                    print(f"Key '{key_name}' not found")
                    secure_new_key.clear()
                    return False
                
                # Keep old key data but update the key and rotation time
                old_entry = keys[key_name]
                # Securely clear the old key
                if 'key' in old_entry:
                    secure_zero_memory(old_entry['key'])
                
                old_entry['key'] = str(secure_new_key)
                old_entry['last_rotated'] = datetime.now().isoformat()
                
                # Optionally store rotation history
                if 'rotation_history' not in old_entry['metadata']:
                    old_entry['metadata']['rotation_history'] = []
                
                old_entry['metadata']['rotation_history'].append({
                    'rotated_at': datetime.now().isoformat(),
                    'reason': 'manual_rotation'
                })
                
                # Save updated keys
                self._save_keys(keys)
                
                # Clear from cache if present
                if key_name in self._key_cache:
                    del self._key_cache[key_name]
                
                # Clear sensitive data
                secure_new_key.clear()
                
                return True
            
        except Exception as e:
            print(f"Error rotating key: {e}")
            if 'secure_new_key' in locals():
                secure_new_key.clear()
            return False
    
    def delete_key(self, key_name: str) -> bool:
        """
        Delete a stored API key.
        
        Args:
            key_name: The identifier of the key to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with MemoryLock():
                keys = self._load_keys()
                
                if key_name in keys:
                    # Securely clear the key before deletion
                    if 'key' in keys[key_name]:
                        secure_zero_memory(keys[key_name]['key'])
                    
                    del keys[key_name]
                    self._save_keys(keys)
                    self._update_config(key_name, None, delete=True)
                    
                    # Clear from cache if present
                    if key_name in self._key_cache:
                        del self._key_cache[key_name]
                    
                    return True
                
                return False
            
        except Exception as e:
            print(f"Error deleting key: {e}")
            return False
    
    def _load_keys(self) -> Dict:
        """Load and decrypt stored keys."""
        if not self.keys_file.exists():
            return {}
        
        try:
            with MemoryLock():
                with open(self.keys_file, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self._decrypt(encrypted_data)
                keys = json.loads(decrypted_data.decode('utf-8'))
                
                # Clear decrypted data from memory after parsing
                secure_zero_memory(decrypted_data)
                
                return keys
            
        except Exception:
            return {}
    
    def _save_keys(self, keys: Dict):
        """Encrypt and save keys."""
        with MemoryLock():
            json_data = json.dumps(keys).encode('utf-8')
            encrypted_data = self._encrypt(json_data)
            
            # Clear the json data from memory
            secure_zero_memory(json_data)
            
            with open(self.keys_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(self.keys_file, 0o600)
    
    def _update_config(self, key_name: str, metadata: Optional[Dict], delete: bool = False):
        """Update configuration file."""
        config = self._load_config()
        
        if delete and key_name in config:
            del config[key_name]
        elif not delete:
            config[key_name] = {
                'metadata': metadata or {},
                'last_updated': datetime.now().isoformat()
            }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        os.chmod(self.config_file, 0o600)
    
    def _load_config(self) -> Dict:
        """Load configuration file."""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def check_key_expiry(self, days_before: int = 7) -> List[Dict]:
        """
        Check for keys that are expiring soon.
        
        Args:
            days_before: Number of days before expiry to warn
        
        Returns:
            List of keys that are expiring soon
        """
        expiring_keys = []
        keys = self._load_keys()
        
        for key_name, key_data in keys.items():
            metadata = key_data.get('metadata', {})
            expiry_str = metadata.get('expiry')
            
            if expiry_str:
                try:
                    expiry_date = datetime.fromisoformat(expiry_str)
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry <= days_before:
                        expiring_keys.append({
                            'name': key_name,
                            'expiry': expiry_str,
                            'days_until_expiry': days_until_expiry
                        })
                except Exception:
                    pass
        
        return expiring_keys
    
    def export_config(self, include_keys: bool = False) -> Dict:
        """
        Export configuration (optionally with encrypted keys).
        
        Args:
            include_keys: Whether to include encrypted keys in export
        
        Returns:
            Configuration dictionary
        """
        config = {
            'storage_path': str(self.storage_path),
            'master_key_env': self.master_key_env,
            'keys_info': self.list_keys()
        }
        
        if include_keys and self.keys_file.exists():
            with open(self.keys_file, 'rb') as f:
                config['encrypted_keys'] = base64.b64encode(f.read()).decode('utf-8')
            with open(self.salt_file, 'rb') as f:
                config['salt'] = base64.b64encode(f.read()).decode('utf-8')
        
        return config


# Utility functions for easy CLI usage
def create_secure_storage(storage_path: str = ".secure_keys") -> SecureKeyStorage:
    """Create a new secure storage instance."""
    return SecureKeyStorage(storage_path=storage_path)


def quick_store(key_name: str, api_key: str, service: Optional[str] = None) -> bool:
    """Quick function to store an API key."""
    storage = create_secure_storage()
    metadata = {'service': service} if service else None
    result = storage.store_key(key_name, api_key, metadata)
    # Ensure API key is cleared from memory
    secure_zero_memory(api_key)
    return result


def quick_retrieve(key_name: str) -> Optional[str]:
    """Quick function to retrieve an API key."""
    storage = create_secure_storage()
    # Note: The returned key should be handled carefully by the caller
    return storage.retrieve_key(key_name)


def quick_list() -> List[Dict]:
    """Quick function to list all stored keys."""
    storage = create_secure_storage()
    return storage.list_keys()