"""
User Interface for API Key Storage System
Provides CLI and programmatic interfaces for key management
"""

import os
import sys
import getpass
import json
from datetime import datetime
from typing import Optional, Dict, List
import argparse
from tabulate import tabulate

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api_key_storage import APIKeyStorage, SecurityException


class APIKeyManager:
    """High-level interface for API key management"""
    
    def __init__(self, storage_path: str = "./keys", use_password: bool = True):
        """Initialize the API Key Manager"""
        self.storage_path = storage_path
        
        if use_password:
            password = getpass.getpass("Enter master password: ")
            self.storage = APIKeyStorage(storage_path=storage_path, master_password=password)
        else:
            self.storage = APIKeyStorage(storage_path=storage_path)
    
    def add_key_interactive(self):
        """Interactively add a new API key"""
        print("\n=== Add New API Key ===")
        
        service = input("Service name (e.g., github, aws): ").strip()
        if not service:
            print("Error: Service name is required")
            return None
        
        api_key = getpass.getpass("API Key (hidden): ").strip()
        if not api_key:
            print("Error: API key is required")
            return None
        
        user = input("User/Owner: ").strip()
        if not user:
            print("Error: User is required")
            return None
        
        # Optional metadata
        print("\nOptional metadata (press Enter to skip):")
        environment = input("Environment (prod/dev/staging): ").strip()
        description = input("Description: ").strip()
        
        metadata = {}
        if environment:
            metadata["environment"] = environment
        if description:
            metadata["description"] = description
        
        try:
            key_id = self.storage.add_api_key(service, api_key, user, metadata)
            print(f"\n✓ API key added successfully!")
            print(f"Key ID: {key_id}")
            print("Store this ID securely - you'll need it to retrieve the key")
            return key_id
        except Exception as e:
            print(f"\n✗ Error adding key: {str(e)}")
            return None
    
    def get_key_interactive(self):
        """Interactively retrieve an API key"""
        print("\n=== Retrieve API Key ===")
        
        key_id = input("Key ID: ").strip()
        if not key_id:
            print("Error: Key ID is required")
            return None
        
        user = input("User requesting access: ").strip()
        if not user:
            print("Error: User is required")
            return None
        
        try:
            api_key = self.storage.get_api_key(key_id, user)
            if api_key:
                print(f"\n✓ API Key retrieved successfully!")
                print(f"Key: {api_key}")
                
                # Show warning
                print("\n⚠️  WARNING: This key is sensitive. Handle with care!")
                print("Consider copying it directly to your application.")
            else:
                print("\n✗ Key not found or access denied")
            
            return api_key
        except Exception as e:
            print(f"\n✗ Error retrieving key: {str(e)}")
            return None
    
    def list_keys_interactive(self, show_inactive: bool = False):
        """Display all keys in a formatted table"""
        print("\n=== API Keys List ===")
        
        user = input("User requesting list (or 'admin' for all): ").strip()
        if not user:
            user = "admin"
        
        try:
            keys = self.storage.list_keys(user, include_inactive=show_inactive)
            
            if not keys:
                print("\nNo keys found")
                return
            
            # Prepare table data
            table_data = []
            for key in keys:
                status = "✓ Active" if key.get("active", True) else "✗ Revoked"
                last_access = key.get("last_accessed", "Never")
                if last_access != "Never":
                    last_access = datetime.fromisoformat(last_access).strftime("%Y-%m-%d %H:%M")
                
                table_data.append([
                    key["key_id"][:8] + "...",  # Truncate for display
                    key["service"],
                    key["user"],
                    status,
                    key.get("access_count", 0),
                    last_access,
                    key.get("metadata", {}).get("environment", "N/A")
                ])
            
            headers = ["Key ID", "Service", "Owner", "Status", "Access Count", "Last Access", "Environment"]
            print(f"\nTotal keys: {len(keys)}")
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
        except Exception as e:
            print(f"\n✗ Error listing keys: {str(e)}")
    
    def rotate_key_interactive(self):
        """Interactively rotate an API key"""
        print("\n=== Rotate API Key ===")
        
        key_id = input("Key ID to rotate: ").strip()
        if not key_id:
            print("Error: Key ID is required")
            return False
        
        new_api_key = getpass.getpass("New API Key (hidden): ").strip()
        if not new_api_key:
            print("Error: New API key is required")
            return False
        
        user = input("User performing rotation: ").strip()
        if not user:
            print("Error: User is required")
            return False
        
        confirm = input("\n⚠️  This will revoke the old key. Continue? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Rotation cancelled")
            return False
        
        try:
            success = self.storage.rotate_key(key_id, new_api_key, user)
            if success:
                print("\n✓ Key rotated successfully!")
                print("Old key has been revoked")
                print("New key is now active")
            else:
                print("\n✗ Failed to rotate key")
            
            return success
        except Exception as e:
            print(f"\n✗ Error rotating key: {str(e)}")
            return False
    
    def revoke_key_interactive(self):
        """Interactively revoke an API key"""
        print("\n=== Revoke API Key ===")
        
        key_id = input("Key ID to revoke: ").strip()
        if not key_id:
            print("Error: Key ID is required")
            return False
        
        user = input("User performing revocation: ").strip()
        if not user:
            print("Error: User is required")
            return False
        
        # Show key details first
        keys = self.storage.list_keys(user)
        key_info = next((k for k in keys if k["key_id"] == key_id), None)
        
        if key_info:
            print(f"\nKey Details:")
            print(f"  Service: {key_info['service']}")
            print(f"  Owner: {key_info['user']}")
            print(f"  Created: {datetime.fromisoformat(key_info['created_at']).strftime('%Y-%m-%d %H:%M')}")
            print(f"  Status: {'Active' if key_info.get('active', True) else 'Already Revoked'}")
        
        confirm = input("\n⚠️  This action cannot be undone. Continue? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Revocation cancelled")
            return False
        
        try:
            success = self.storage.revoke_key(key_id, user)
            if success:
                print("\n✓ Key revoked successfully!")
            else:
                print("\n✗ Failed to revoke key (may not exist)")
            
            return success
        except Exception as e:
            print(f"\n✗ Error revoking key: {str(e)}")
            return False
    
    def check_expiring_keys(self, days: int = 90):
        """Check and display keys that need rotation"""
        print(f"\n=== Keys Older Than {days} Days ===")
        
        try:
            expiring_keys = self.storage.check_key_expiry(days)
            
            if not expiring_keys:
                print(f"\n✓ No keys older than {days} days")
                return
            
            print(f"\n⚠️  Found {len(expiring_keys)} keys that should be rotated:")
            
            table_data = []
            for key in expiring_keys:
                created = datetime.fromisoformat(key["created_at"])
                table_data.append([
                    key["key_id"][:8] + "...",
                    key["service"],
                    created.strftime("%Y-%m-%d"),
                    f"{key['days_old']} days"
                ])
            
            headers = ["Key ID", "Service", "Created", "Age"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            print("\nRecommendation: Rotate these keys for security best practices")
            
        except Exception as e:
            print(f"\n✗ Error checking expiry: {str(e)}")
    
    def export_audit_log(self, output_file: Optional[str] = None):
        """Export audit log"""
        print("\n=== Export Audit Log ===")
        
        try:
            audit_log = self.storage.export_audit_log()
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(audit_log)
                print(f"\n✓ Audit log exported to: {output_file}")
            else:
                print("\n" + audit_log)
            
        except Exception as e:
            print(f"\n✗ Error exporting audit log: {str(e)}")
    
    def display_menu(self):
        """Display interactive menu"""
        while True:
            print("\n" + "="*50)
            print("API Key Storage System")
            print("="*50)
            print("1. Add new API key")
            print("2. Retrieve API key")
            print("3. List all keys")
            print("4. Rotate API key")
            print("5. Revoke API key")
            print("6. Check expiring keys")
            print("7. Export audit log")
            print("8. Exit")
            print("="*50)
            
            choice = input("\nSelect option (1-8): ").strip()
            
            if choice == "1":
                self.add_key_interactive()
            elif choice == "2":
                self.get_key_interactive()
            elif choice == "3":
                show_inactive = input("Show revoked keys? (yes/no): ").strip().lower() == "yes"
                self.list_keys_interactive(show_inactive)
            elif choice == "4":
                self.rotate_key_interactive()
            elif choice == "5":
                self.revoke_key_interactive()
            elif choice == "6":
                days = input("Check keys older than (days) [90]: ").strip()
                days = int(days) if days else 90
                self.check_expiring_keys(days)
            elif choice == "7":
                output_file = input("Output file (leave empty for console): ").strip()
                self.export_audit_log(output_file if output_file else None)
            elif choice == "8":
                print("\nGoodbye!")
                break
            else:
                print("\n✗ Invalid option. Please try again.")
            
            input("\nPress Enter to continue...")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="Secure API Key Storage System")
    parser.add_argument("--storage", default="./keys", help="Storage directory path")
    parser.add_argument("--no-password", action="store_true", help="Use file-based encryption instead of password")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add new API key")
    add_parser.add_argument("service", help="Service name")
    add_parser.add_argument("--user", required=True, help="User/owner")
    add_parser.add_argument("--env", help="Environment (prod/dev/staging)")
    
    # Get command
    get_parser = subparsers.add_parser("get", help="Retrieve API key")
    get_parser.add_argument("key_id", help="Key ID")
    get_parser.add_argument("--user", required=True, help="User requesting access")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List all keys")
    list_parser.add_argument("--user", default="admin", help="User requesting list")
    list_parser.add_argument("--all", action="store_true", help="Include revoked keys")
    
    # Rotate command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate API key")
    rotate_parser.add_argument("key_id", help="Key ID to rotate")
    rotate_parser.add_argument("--user", required=True, help="User performing rotation")
    
    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke API key")
    revoke_parser.add_argument("key_id", help="Key ID to revoke")
    revoke_parser.add_argument("--user", required=True, help="User performing revocation")
    
    # Check expiry command
    expiry_parser = subparsers.add_parser("check-expiry", help="Check expiring keys")
    expiry_parser.add_argument("--days", type=int, default=90, help="Days threshold")
    
    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Export audit log")
    audit_parser.add_argument("--output", help="Output file")
    
    args = parser.parse_args()
    
    # Initialize manager
    manager = APIKeyManager(
        storage_path=args.storage,
        use_password=not args.no_password
    )
    
    # Handle commands
    if args.command == "add":
        api_key = getpass.getpass("API Key: ")
        metadata = {"environment": args.env} if args.env else {}
        key_id = manager.storage.add_api_key(args.service, api_key, args.user, metadata)
        print(f"Key added successfully. ID: {key_id}")
    
    elif args.command == "get":
        api_key = manager.storage.get_api_key(args.key_id, args.user)
        if api_key:
            print(f"API Key: {api_key}")
        else:
            print("Key not found or access denied")
    
    elif args.command == "list":
        manager.list_keys_interactive(args.all)
    
    elif args.command == "rotate":
        new_key = getpass.getpass("New API Key: ")
        success = manager.storage.rotate_key(args.key_id, new_key, args.user)
        print("Key rotated successfully" if success else "Failed to rotate key")
    
    elif args.command == "revoke":
        success = manager.storage.revoke_key(args.key_id, args.user)
        print("Key revoked successfully" if success else "Failed to revoke key")
    
    elif args.command == "check-expiry":
        manager.check_expiring_keys(args.days)
    
    elif args.command == "audit":
        manager.export_audit_log(args.output)
    
    else:
        # Interactive mode
        manager.display_menu()


if __name__ == "__main__":
    main()