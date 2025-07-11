#!/usr/bin/env python3
"""
Example usage of the Secure API Key Storage system

This script demonstrates how to use the secure storage system programmatically.
"""

import os
from datetime import datetime, timedelta

from secure_storage import SecureKeyStorage
from config_manager import ConfigurationManager, APIKeyConfig, ServiceProvider
from key_rotation import KeyRotationManager


def basic_storage_example():
    """Demonstrate basic key storage and retrieval."""
    print("=== Basic Storage Example ===")
    
    # Create storage instance
    storage = SecureKeyStorage()
    
    # Store a key
    api_key = "sk-1234567890abcdef"  # Example key
    metadata = {
        'service': 'openai',
        'environment': 'production',
        'created_by': 'admin'
    }
    
    if storage.store_key('openai_prod', api_key, metadata):
        print("✓ Key stored successfully")
    
    # Retrieve the key
    retrieved_key = storage.retrieve_key('openai_prod')
    if retrieved_key == api_key:
        print("✓ Key retrieved successfully")
    
    # List all keys
    keys = storage.list_keys()
    print(f"\nStored keys: {len(keys)}")
    for key in keys:
        print(f"  - {key['name']} (created: {key['created'][:10]})")
    
    print()


def profile_management_example():
    """Demonstrate profile-based configuration management."""
    print("=== Profile Management Example ===")
    
    # Create configuration manager
    manager = ConfigurationManager()
    
    # Create profiles
    manager.create_profile('development', 'Development environment keys')
    manager.create_profile('production', 'Production environment keys')
    
    print("✓ Created profiles")
    
    # Add keys to development profile
    dev_openai_config = APIKeyConfig(
        name='openai',
        provider=ServiceProvider.OPENAI,
        environment='development',
        endpoint='https://api.openai.com/v1',
        rate_limit=1000,
        tags=['gpt-4', 'development']
    )
    
    manager.add_api_key('development', dev_openai_config, 'sk-dev-key-123')
    
    # Add keys to production profile
    prod_openai_config = APIKeyConfig(
        name='openai',
        provider=ServiceProvider.OPENAI,
        environment='production',
        endpoint='https://api.openai.com/v1',
        rate_limit=10000,
        expiry=(datetime.now() + timedelta(days=90)).isoformat(),
        tags=['gpt-4', 'production']
    )
    
    manager.add_api_key('production', prod_openai_config, 'sk-prod-key-456')
    
    print("✓ Added API keys to profiles")
    
    # List profiles
    profiles = manager.list_profiles()
    print(f"\nProfiles: {len(profiles)}")
    for profile in profiles:
        print(f"  - {profile['name']}: {profile['num_keys']} keys")
    
    # Load a profile's environment
    env_vars = manager.load_profile_environment('development')
    print(f"\nDevelopment environment variables: {len(env_vars)}")
    for var_name in env_vars:
        print(f"  - {var_name}")
    
    print()


def key_rotation_example():
    """Demonstrate key rotation capabilities."""
    print("=== Key Rotation Example ===")
    
    # Setup
    manager = ConfigurationManager()
    rotation_manager = KeyRotationManager(manager)
    
    # Create a profile with a key
    if 'rotation_test' not in manager.config['profiles']:
        manager.create_profile('rotation_test', 'Test rotation profile')
        
        test_config = APIKeyConfig(
            name='test_key',
            provider=ServiceProvider.CUSTOM,
            environment='test',
            expiry=(datetime.now() + timedelta(days=7)).isoformat()
        )
        
        manager.add_api_key('rotation_test', test_config, 'old-test-key-123')
        print("✓ Created test profile and key")
    
    # Perform rotation
    success, error = rotation_manager.rotate_key(
        'rotation_test', 
        'test_key', 
        'new-test-key-456',
        reason='example_rotation'
    )
    
    if success:
        print("✓ Key rotated successfully")
    else:
        print(f"✗ Rotation failed: {error}")
    
    # Check rotation history
    history = rotation_manager.get_rotation_history('rotation_test')
    print(f"\nRotation history: {len(history)} events")
    for event in history[-3:]:  # Show last 3 events
        print(f"  - {event['timestamp'][:19]}: {event['status']} ({event['reason']})")
    
    # Check for expiring keys
    expiring = manager.check_expiring_keys(days_before=30)
    if expiring:
        print(f"\nKeys expiring within 30 days: {len(expiring)}")
        for key in expiring:
            print(f"  - {key['profile']}/{key['key_name']} expires in {key['days_until_expiry']} days")
    
    print()


def security_audit_example():
    """Demonstrate security audit features."""
    print("=== Security Audit Example ===")
    
    manager = ConfigurationManager()
    rotation_manager = KeyRotationManager(manager)
    
    # Generate rotation report
    report = rotation_manager.generate_rotation_report(days=30)
    
    print("Rotation Report (Last 30 days):")
    print(f"  Total rotations: {report['summary']['total_rotations']}")
    print(f"  Successful: {report['summary']['successful']}")
    print(f"  Failed: {report['summary']['failed']}")
    print(f"  Rolled back: {report['summary']['rolled_back']}")
    
    if report['by_provider']:
        print("\n  By Provider:")
        for provider, count in report['by_provider'].items():
            print(f"    - {provider}: {count}")
    
    if report['failures']:
        print("\n  Recent Failures:")
        for failure in report['failures'][:3]:
            print(f"    - {failure['profile']}/{failure['key_name']}: {failure['error']}")
    
    print()


def cleanup_example():
    """Demonstrate cleanup operations."""
    print("=== Cleanup Example ===")
    
    storage = SecureKeyStorage()
    
    # Delete test keys
    test_keys = ['openai_prod', 'test_key']
    for key_name in test_keys:
        if storage.delete_key(key_name):
            print(f"✓ Deleted key '{key_name}'")
    
    print()


def main():
    """Run all examples."""
    print("Secure API Key Storage - Example Usage\n")
    
    # Set master key for examples (in production, this should be in environment)
    if 'API_KEY_MASTER' not in os.environ:
        os.environ['API_KEY_MASTER'] = 'example-master-key-do-not-use-in-production'
        print("⚠️  Using example master key. In production, set API_KEY_MASTER environment variable.\n")
    
    try:
        basic_storage_example()
        profile_management_example()
        key_rotation_example()
        security_audit_example()
        # cleanup_example()  # Uncomment to clean up test data
        
        print("All examples completed successfully!")
        print("\nTo use the CLI, run: python cli.py --help")
        
    except Exception as e:
        print(f"Error running examples: {e}")


if __name__ == '__main__':
    main()