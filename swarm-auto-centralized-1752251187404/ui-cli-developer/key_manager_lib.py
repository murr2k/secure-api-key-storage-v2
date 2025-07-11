"""
Key Manager Library

A Python library wrapper for the Secure Key Manager CLI, providing
programmatic access to key management functionality.
"""

import subprocess
import json
import os
from typing import Dict, List, Optional, Union
from pathlib import Path
from datetime import datetime
import tempfile
import contextlib


class KeyManagerError(Exception):
    """Base exception for Key Manager errors."""
    pass


class AuthenticationError(KeyManagerError):
    """Raised when master password authentication fails."""
    pass


class KeyNotFoundError(KeyManagerError):
    """Raised when a requested key is not found."""
    pass


class KeyManager:
    """
    Python wrapper for the Secure Key Manager CLI.
    
    Provides programmatic access to all key management operations.
    """
    
    def __init__(self, cli_path: str = "./key-manager-cli.py", 
                 master_password: Optional[str] = None,
                 auto_unlock: bool = True):
        """
        Initialize the Key Manager.
        
        Args:
            cli_path: Path to the key-manager CLI executable
            master_password: Master password for the key manager
            auto_unlock: Whether to automatically unlock for each operation
        """
        self.cli_path = Path(cli_path).absolute()
        self.master_password = master_password or os.environ.get('KEY_MANAGER_PASSWORD')
        self.auto_unlock = auto_unlock
        
        if not self.cli_path.exists():
            raise KeyManagerError(f"CLI not found at {self.cli_path}")
    
    def _run_command(self, args: List[str], input_text: Optional[str] = None) -> Dict:
        """
        Run a CLI command and return the result.
        
        Args:
            args: Command arguments
            input_text: Input to send to the command
            
        Returns:
            Dict with 'stdout', 'stderr', and 'returncode'
        """
        cmd = [str(self.cli_path)] + args
        
        # Add master password to input if needed and auto_unlock is enabled
        if self.auto_unlock and self.master_password and input_text is None:
            input_text = self.master_password + '\n'
        elif self.auto_unlock and self.master_password and input_text:
            input_text = self.master_password + '\n' + input_text
        
        try:
            result = subprocess.run(
                cmd,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            raise KeyManagerError("Command timed out")
        except Exception as e:
            raise KeyManagerError(f"Command failed: {e}")
    
    def is_initialized(self) -> bool:
        """Check if the key manager is initialized."""
        config_file = Path.home() / ".secure-keys" / "config.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                    return config.get('salt') is not None
            except:
                pass
        return False
    
    def initialize(self, master_password: str) -> bool:
        """
        Initialize the key manager with a master password.
        
        Args:
            master_password: The master password to use
            
        Returns:
            True if successful
        """
        if len(master_password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        result = self._run_command(['setup'], f"{master_password}\n{master_password}\n")
        
        if result['returncode'] == 0:
            self.master_password = master_password
            return True
        
        raise KeyManagerError(result['stderr'] or "Initialization failed")
    
    def add_key(self, service: str, key_name: str, key_value: str, 
                metadata: Optional[Dict] = None) -> bool:
        """
        Add a new API key.
        
        Args:
            service: Service name (e.g., 'github')
            key_name: Key name (e.g., 'personal')
            key_value: The API key value
            metadata: Optional metadata dictionary
            
        Returns:
            True if successful
        """
        args = ['add', service, key_name, '--key-value', key_value]
        
        if metadata:
            args.extend(['--metadata', json.dumps(metadata)])
        
        result = self._run_command(args)
        
        if result['returncode'] == 0:
            return True
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        raise KeyManagerError(result['stderr'] or "Failed to add key")
    
    def get_key(self, service: str, key_name: str) -> Optional[str]:
        """
        Get a specific API key.
        
        Args:
            service: Service name
            key_name: Key name
            
        Returns:
            The key value or None if not found
        """
        result = self._run_command(['get', service, key_name, '--show'])
        
        if result['returncode'] == 0:
            # Extract the key from output (last line)
            lines = result['stdout'].strip().split('\n')
            if lines:
                # Find the line that contains the actual key
                for line in reversed(lines):
                    # Skip ANSI color codes and formatting
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith('['):
                        return clean_line
            return None
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        if "not found" in result['stderr']:
            raise KeyNotFoundError(f"Key '{key_name}' not found for service '{service}'")
        
        return None
    
    def remove_key(self, service: str, key_name: str, confirm: bool = True) -> bool:
        """
        Remove an API key.
        
        Args:
            service: Service name
            key_name: Key name
            confirm: Whether to confirm deletion
            
        Returns:
            True if successful
        """
        input_text = None
        if confirm:
            input_text = "y\n"
        
        result = self._run_command(['remove', service, key_name], input_text)
        
        if result['returncode'] == 0:
            return True
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        return False
    
    def update_key(self, service: str, key_name: str, new_value: str) -> bool:
        """
        Update an existing key.
        
        Args:
            service: Service name
            key_name: Key name
            new_value: New key value
            
        Returns:
            True if successful
        """
        result = self._run_command(
            ['rotate', service, key_name, '--new-value', new_value]
        )
        
        if result['returncode'] == 0:
            return True
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        raise KeyManagerError(result['stderr'] or "Failed to update key")
    
    def rotate_key(self, service: str, key_name: str, 
                   new_value: Optional[str] = None) -> Optional[str]:
        """
        Rotate an API key.
        
        Args:
            service: Service name
            key_name: Key name
            new_value: New value (auto-generated if None)
            
        Returns:
            The new key value if auto-generated, None otherwise
        """
        args = ['rotate', service, key_name]
        
        if new_value:
            args.extend(['--new-value', new_value])
            
        result = self._run_command(args)
        
        if result['returncode'] == 0:
            if not new_value:
                # Extract generated key from output
                lines = result['stdout'].strip().split('\n')
                for line in lines:
                    if "New key:" in line:
                        return line.split("New key:")[1].strip()
            return new_value
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        raise KeyManagerError(result['stderr'] or "Failed to rotate key")
    
    def list_services(self) -> List[Dict[str, Union[str, List[str]]]]:
        """
        List all configured services.
        
        Returns:
            List of service dictionaries with 'name', 'keys', and 'created'
        """
        result = self._run_command(['list'])
        
        if result['returncode'] != 0:
            if "Invalid master password" in result['stderr']:
                raise AuthenticationError("Invalid master password")
            return []
        
        # Parse the output
        services = []
        lines = result['stdout'].strip().split('\n')
        
        # Simple parsing - this would need to be more robust for production
        for line in lines:
            if '│' in line and not line.startswith('┌') and not line.startswith('├'):
                parts = [p.strip() for p in line.split('│')[1:-1]]
                if len(parts) >= 3 and parts[0] != 'Service':
                    services.append({
                        'name': parts[0],
                        'keys': [k.strip() for k in parts[1].split(',')],
                        'created': parts[2]
                    })
        
        return services
    
    def backup(self, backup_name: Optional[str] = None) -> str:
        """
        Create a backup of all keys.
        
        Args:
            backup_name: Optional backup name
            
        Returns:
            Path to the backup file
        """
        args = ['backup']
        if backup_name:
            args.extend(['--name', backup_name])
        
        result = self._run_command(args)
        
        if result['returncode'] == 0:
            # Extract backup path from output
            lines = result['stdout'].strip().split('\n')
            for line in lines:
                if "Backup created:" in line:
                    return line.split("Backup created:")[1].strip()
            return "backup created"
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        raise KeyManagerError(result['stderr'] or "Failed to create backup")
    
    def restore(self, backup_name: str) -> bool:
        """
        Restore from a backup.
        
        Args:
            backup_name: Name of the backup to restore
            
        Returns:
            True if successful
        """
        result = self._run_command(['restore', backup_name], "y\n")
        
        if result['returncode'] == 0:
            return True
        
        if "Invalid master password" in result['stderr']:
            raise AuthenticationError("Invalid master password")
        
        raise KeyManagerError(result['stderr'] or "Failed to restore backup")
    
    def list_backups(self) -> List[Dict[str, str]]:
        """
        List available backups.
        
        Returns:
            List of backup dictionaries
        """
        result = self._run_command(['restore', 'list'])
        
        if result['returncode'] != 0:
            if "Invalid master password" in result['stderr']:
                raise AuthenticationError("Invalid master password")
            return []
        
        # Parse backup list
        backups = []
        lines = result['stdout'].strip().split('\n')
        
        for line in lines:
            if '│' in line and not line.startswith('┌'):
                parts = [p.strip() for p in line.split('│')[1:-1]]
                if len(parts) >= 3 and parts[0] != 'Name':
                    backups.append({
                        'name': parts[0],
                        'created': parts[1],
                        'size': parts[2]
                    })
        
        return backups
    
    @contextlib.contextmanager
    def temporary_key(self, service: str, key_name: str, key_value: str):
        """
        Context manager for temporary keys.
        
        Args:
            service: Service name
            key_name: Key name
            key_value: Key value
            
        Usage:
            with km.temporary_key('test', 'temp', 'abc123') as key:
                # Use the key
                pass
            # Key is automatically removed
        """
        try:
            self.add_key(service, key_name, key_value)
            yield key_value
        finally:
            try:
                self.remove_key(service, key_name, confirm=False)
            except:
                pass
    
    def export_env(self, mappings: Dict[str, tuple]) -> Dict[str, str]:
        """
        Export keys as environment variables.
        
        Args:
            mappings: Dict mapping env var names to (service, key_name) tuples
            
        Returns:
            Dictionary of environment variables
            
        Example:
            env_vars = km.export_env({
                'GITHUB_TOKEN': ('github', 'personal'),
                'AWS_ACCESS_KEY': ('aws', 'access-key')
            })
        """
        env_vars = {}
        
        for env_name, (service, key_name) in mappings.items():
            try:
                value = self.get_key(service, key_name)
                if value:
                    env_vars[env_name] = value
                    os.environ[env_name] = value
            except KeyNotFoundError:
                pass
        
        return env_vars
    
    def bulk_add(self, keys: List[Dict]) -> Dict[str, bool]:
        """
        Add multiple keys at once.
        
        Args:
            keys: List of key dictionaries with 'service', 'key_name', 'value'
            
        Returns:
            Dictionary mapping "service/key_name" to success status
        """
        results = {}
        
        for key_info in keys:
            key_id = f"{key_info['service']}/{key_info['key_name']}"
            try:
                success = self.add_key(
                    key_info['service'],
                    key_info['key_name'],
                    key_info['value'],
                    key_info.get('metadata')
                )
                results[key_id] = success
            except Exception as e:
                results[key_id] = False
        
        return results
    
    def search_keys(self, pattern: str) -> List[Dict]:
        """
        Search for keys matching a pattern.
        
        Args:
            pattern: Search pattern (matches service or key name)
            
        Returns:
            List of matching keys
        """
        services = self.list_services()
        matches = []
        
        for service in services:
            # Check if service name matches
            if pattern.lower() in service['name'].lower():
                for key in service['keys']:
                    matches.append({
                        'service': service['name'],
                        'key_name': key,
                        'created': service['created']
                    })
            else:
                # Check if any key name matches
                for key in service['keys']:
                    if pattern.lower() in key.lower():
                        matches.append({
                            'service': service['name'],
                            'key_name': key,
                            'created': service['created']
                        })
        
        return matches


# Convenience functions
def quick_get(service: str, key_name: str, password: Optional[str] = None) -> Optional[str]:
    """
    Quick function to get a key without creating a KeyManager instance.
    
    Args:
        service: Service name
        key_name: Key name
        password: Master password (uses env var if not provided)
        
    Returns:
        Key value or None
    """
    km = KeyManager(master_password=password)
    try:
        return km.get_key(service, key_name)
    except:
        return None


def quick_add(service: str, key_name: str, key_value: str, 
              password: Optional[str] = None) -> bool:
    """
    Quick function to add a key without creating a KeyManager instance.
    
    Args:
        service: Service name
        key_name: Key name
        key_value: Key value
        password: Master password (uses env var if not provided)
        
    Returns:
        True if successful
    """
    km = KeyManager(master_password=password)
    try:
        return km.add_key(service, key_name, key_value)
    except:
        return False