#!/usr/bin/env python3
"""
Command Line Interface for Secure API Key Storage

This module provides a user-friendly CLI for managing API keys securely.
"""

import os
import sys
import argparse
import getpass
from datetime import datetime, timedelta
from tabulate import tabulate
from typing import Optional

from secure_storage import SecureKeyStorage, quick_store, quick_retrieve, quick_list
from config_manager import ConfigurationManager, APIKeyConfig, ServiceProvider, quick_setup, load_environment
from key_rotation import KeyRotationManager, openai_rotation_callback, aws_rotation_callback


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Secure API Key Storage - Manage your API keys securely",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Store a new API key
  %(prog)s store mykey --service openai
  
  # Retrieve a key
  %(prog)s get mykey
  
  # List all keys
  %(prog)s list
  
  # Create a profile
  %(prog)s profile create dev --description "Development environment"
  
  # Add key to profile
  %(prog)s profile add-key dev openai_key --provider openai
  
  # Load profile environment
  %(prog)s profile load dev
  
  # Rotate a key
  %(prog)s rotate dev openai_key
  
  # Check expiring keys
  %(prog)s check-expiry --days 30
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Store command
    store_parser = subparsers.add_parser('store', help='Store a new API key')
    store_parser.add_argument('name', help='Unique name for the key')
    store_parser.add_argument('--service', help='Service name (e.g., openai, aws)')
    store_parser.add_argument('--expiry', help='Expiry date (YYYY-MM-DD)')
    store_parser.add_argument('--key', help='API key (will prompt if not provided)')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Retrieve an API key')
    get_parser.add_argument('name', help='Name of the key to retrieve')
    get_parser.add_argument('--show', action='store_true', help='Display the key value')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all stored keys')
    list_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed information')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a stored key')
    delete_parser.add_argument('name', help='Name of the key to delete')
    delete_parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompt')
    
    # Profile commands
    profile_parser = subparsers.add_parser('profile', help='Manage configuration profiles')
    profile_subparsers = profile_parser.add_subparsers(dest='profile_command')
    
    # Profile create
    profile_create = profile_subparsers.add_parser('create', help='Create a new profile')
    profile_create.add_argument('name', help='Profile name')
    profile_create.add_argument('--description', help='Profile description')
    
    # Profile list
    profile_list = profile_subparsers.add_parser('list', help='List all profiles')
    
    # Profile add-key
    profile_add_key = profile_subparsers.add_parser('add-key', help='Add key to profile')
    profile_add_key.add_argument('profile', help='Profile name')
    profile_add_key.add_argument('key_name', help='Key name')
    profile_add_key.add_argument('--provider', required=True, help='Provider (openai, aws, etc.)')
    profile_add_key.add_argument('--environment', default='production', help='Environment')
    profile_add_key.add_argument('--endpoint', help='API endpoint')
    profile_add_key.add_argument('--expiry', help='Expiry date (YYYY-MM-DD)')
    profile_add_key.add_argument('--key', help='API key (will prompt if not provided)')
    
    # Profile load
    profile_load = profile_subparsers.add_parser('load', help='Load profile environment')
    profile_load.add_argument('profile', help='Profile name')
    profile_load.add_argument('--export', action='store_true', help='Export as shell commands')
    
    # Rotate command
    rotate_parser = subparsers.add_parser('rotate', help='Rotate an API key')
    rotate_parser.add_argument('profile', help='Profile name')
    rotate_parser.add_argument('key_name', help='Key name')
    rotate_parser.add_argument('--new-key', help='New key value (will generate if not provided)')
    rotate_parser.add_argument('--reason', default='manual', help='Reason for rotation')
    rotate_parser.add_argument('--test', action='store_true', help='Test mode - validate only')
    
    # Rollback command
    rollback_parser = subparsers.add_parser('rollback', help='Rollback key rotation')
    rollback_parser.add_argument('profile', help='Profile name')
    rollback_parser.add_argument('key_name', help='Key name')
    
    # Check expiry command
    check_expiry_parser = subparsers.add_parser('check-expiry', help='Check for expiring keys')
    check_expiry_parser.add_argument('--days', type=int, default=7, help='Days before expiry')
    check_expiry_parser.add_argument('--auto-rotate', action='store_true', help='Automatically rotate expiring keys')
    
    # Rotation history command
    history_parser = subparsers.add_parser('history', help='View rotation history')
    history_parser.add_argument('--profile', help='Filter by profile')
    history_parser.add_argument('--key', help='Filter by key name')
    history_parser.add_argument('--days', type=int, default=30, help='Number of days to show')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export configuration')
    export_parser.add_argument('profile', help='Profile to export')
    export_parser.add_argument('output', help='Output file (json or yaml)')
    export_parser.add_argument('--include-keys', action='store_true', help='Include encrypted keys')
    
    # Import command
    import_parser = subparsers.add_parser('import', help='Import configuration')
    import_parser.add_argument('file', help='Import file')
    import_parser.add_argument('--profile', help='New profile name')
    
    # Quick setup command
    setup_parser = subparsers.add_parser('setup', help='Quick setup for common providers')
    setup_parser.add_argument('provider', choices=['openai', 'anthropic', 'aws', 'google'], help='Provider name')
    setup_parser.add_argument('--profile', default='default', help='Profile name')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute commands
    try:
        if args.command == 'store':
            handle_store(args)
        elif args.command == 'get':
            handle_get(args)
        elif args.command == 'list':
            handle_list(args)
        elif args.command == 'delete':
            handle_delete(args)
        elif args.command == 'profile':
            handle_profile(args)
        elif args.command == 'rotate':
            handle_rotate(args)
        elif args.command == 'rollback':
            handle_rollback(args)
        elif args.command == 'check-expiry':
            handle_check_expiry(args)
        elif args.command == 'history':
            handle_history(args)
        elif args.command == 'export':
            handle_export(args)
        elif args.command == 'import':
            handle_import(args)
        elif args.command == 'setup':
            handle_setup(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def handle_store(args):
    """Handle the store command."""
    # Get API key
    if args.key:
        api_key = args.key
    else:
        api_key = getpass.getpass("Enter API key: ")
    
    # Prepare metadata
    metadata = {}
    if args.service:
        metadata['service'] = args.service
    if args.expiry:
        metadata['expiry'] = args.expiry
    
    # Store the key
    if quick_store(args.name, api_key, args.service):
        print(f"Successfully stored key '{args.name}'")
    else:
        print(f"Failed to store key '{args.name}'")


def handle_get(args):
    """Handle the get command."""
    api_key = quick_retrieve(args.name)
    
    if api_key:
        if args.show:
            print(f"Key '{args.name}': {api_key}")
        else:
            print(f"Key '{args.name}' found. Use --show to display it.")
            # Copy to clipboard if available
            try:
                import pyperclip
                pyperclip.copy(api_key)
                print("Key copied to clipboard.")
            except ImportError:
                pass
    else:
        print(f"Key '{args.name}' not found.")


def handle_list(args):
    """Handle the list command."""
    keys = quick_list()
    
    if not keys:
        print("No keys stored.")
        return
    
    if args.verbose:
        headers = ['Name', 'Service', 'Created', 'Last Rotated', 'Expiry']
        rows = []
        for key in keys:
            rows.append([
                key['name'],
                key.get('metadata', {}).get('service', 'N/A'),
                key.get('created', 'N/A')[:10],
                key.get('last_rotated', 'N/A')[:10],
                key.get('metadata', {}).get('expiry', 'N/A')
            ])
        print(tabulate(rows, headers=headers, tablefmt='grid'))
    else:
        print("Stored keys:")
        for key in keys:
            service = key.get('metadata', {}).get('service', '')
            if service:
                print(f"  - {key['name']} ({service})")
            else:
                print(f"  - {key['name']}")


def handle_delete(args):
    """Handle the delete command."""
    if not args.confirm:
        response = input(f"Delete key '{args.name}'? (y/N): ")
        if response.lower() != 'y':
            print("Deletion cancelled.")
            return
    
    storage = SecureKeyStorage()
    if storage.delete_key(args.name):
        print(f"Key '{args.name}' deleted.")
    else:
        print(f"Failed to delete key '{args.name}'.")


def handle_profile(args):
    """Handle profile commands."""
    manager = ConfigurationManager()
    
    if args.profile_command == 'create':
        description = args.description or ""
        if manager.create_profile(args.name, description):
            print(f"Profile '{args.name}' created.")
        else:
            print(f"Failed to create profile '{args.name}'.")
    
    elif args.profile_command == 'list':
        profiles = manager.list_profiles()
        if not profiles:
            print("No profiles found.")
            return
        
        headers = ['Name', 'Description', 'Created', 'Keys']
        rows = []
        for profile in profiles:
            rows.append([
                profile['name'],
                profile['description'][:30] + '...' if len(profile['description']) > 30 else profile['description'],
                profile.get('created', 'N/A')[:10],
                profile['num_keys']
            ])
        print(tabulate(rows, headers=headers, tablefmt='grid'))
    
    elif args.profile_command == 'add-key':
        # Get API key
        if args.key:
            api_key = args.key
        else:
            api_key = getpass.getpass("Enter API key: ")
        
        # Create key config
        key_config = APIKeyConfig(
            name=args.key_name,
            provider=ServiceProvider(args.provider.lower()),
            environment=args.environment,
            endpoint=args.endpoint,
            expiry=args.expiry
        )
        
        if manager.add_api_key(args.profile, key_config, api_key):
            print(f"Key '{args.key_name}' added to profile '{args.profile}'.")
        else:
            print(f"Failed to add key to profile.")
    
    elif args.profile_command == 'load':
        env_vars = manager.load_profile_environment(args.profile)
        
        if args.export:
            # Export as shell commands
            for var_name, var_value in env_vars.items():
                print(f'export {var_name}="{var_value}"')
        else:
            # Load into current environment
            load_environment(args.profile)
    
    else:
        print("Unknown profile command.")


def handle_rotate(args):
    """Handle the rotate command."""
    manager = ConfigurationManager()
    rotation_manager = KeyRotationManager(manager)
    
    # Register rotation callbacks
    rotation_manager.register_rotation_callback(ServiceProvider.OPENAI, openai_rotation_callback)
    rotation_manager.register_rotation_callback(ServiceProvider.AWS, aws_rotation_callback)
    
    # Get new key if provided
    new_key = None
    if args.new_key:
        new_key = args.new_key
    elif not args.test:
        response = input("Enter new key (leave empty to auto-generate): ")
        if response:
            new_key = response
    
    # Perform rotation
    success, error = rotation_manager.rotate_key(
        args.profile, args.key_name, new_key, args.reason, args.test
    )
    
    if success:
        if args.test:
            print("Test rotation successful. No changes made.")
        else:
            print(f"Successfully rotated key '{args.key_name}' in profile '{args.profile}'.")
    else:
        print(f"Rotation failed: {error}")


def handle_rollback(args):
    """Handle the rollback command."""
    manager = ConfigurationManager()
    rotation_manager = KeyRotationManager(manager)
    
    success, error = rotation_manager.rollback_rotation(args.profile, args.key_name)
    
    if success:
        print(f"Successfully rolled back key '{args.key_name}' in profile '{args.profile}'.")
    else:
        print(f"Rollback failed: {error}")


def handle_check_expiry(args):
    """Handle the check-expiry command."""
    manager = ConfigurationManager()
    expiring_keys = manager.check_expiring_keys(args.days)
    
    if not expiring_keys:
        print(f"No keys expiring within {args.days} days.")
        return
    
    print(f"Keys expiring within {args.days} days:")
    headers = ['Profile', 'Key Name', 'Provider', 'Expiry', 'Days Until']
    rows = []
    
    for key in expiring_keys:
        rows.append([
            key['profile'],
            key['key_name'],
            key['provider'],
            key['expiry'][:10],
            key['days_until_expiry']
        ])
    
    print(tabulate(rows, headers=headers, tablefmt='grid'))
    
    if args.auto_rotate:
        print("\nStarting automatic rotation...")
        rotation_manager = KeyRotationManager(manager)
        results = rotation_manager.auto_rotate_expiring_keys(args.days, dry_run=False)
        
        for result in results:
            if result['action'] == 'rotated':
                print(f"  ✓ Rotated {result['profile']}/{result['key_name']}")
            else:
                print(f"  ✗ Failed to rotate {result['profile']}/{result['key_name']}: {result.get('error')}")


def handle_history(args):
    """Handle the history command."""
    manager = ConfigurationManager()
    rotation_manager = KeyRotationManager(manager)
    
    history = rotation_manager.get_rotation_history(args.profile, args.key)
    
    if not history:
        print("No rotation history found.")
        return
    
    # Filter by days
    if args.days:
        cutoff = datetime.now() - timedelta(days=args.days)
        history = [h for h in history if datetime.fromisoformat(h['timestamp']) > cutoff]
    
    headers = ['Profile', 'Key', 'Provider', 'Timestamp', 'Status', 'Reason']
    rows = []
    
    for event in history:
        rows.append([
            event['profile'],
            event['key_name'],
            event['provider'],
            event['timestamp'][:19],
            event['status'],
            event['reason']
        ])
    
    print(tabulate(rows, headers=headers, tablefmt='grid'))


def handle_export(args):
    """Handle the export command."""
    manager = ConfigurationManager()
    manager.export_profile(args.profile, args.output, args.include_keys)


def handle_import(args):
    """Handle the import command."""
    manager = ConfigurationManager()
    manager.import_profile(args.file, args.profile)


def handle_setup(args):
    """Handle the setup command."""
    print(f"Setting up {args.provider} API key...")
    api_key = getpass.getpass(f"Enter your {args.provider} API key: ")
    
    if quick_setup(args.provider, api_key, args.profile):
        print(f"Successfully set up {args.provider} in profile '{args.profile}'.")
        print(f"\nTo load this profile: cli.py profile load {args.profile}")
    else:
        print("Setup failed.")


if __name__ == '__main__':
    main()