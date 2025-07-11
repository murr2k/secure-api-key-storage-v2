#!/usr/bin/env python3
"""
Migration script to upgrade existing secure storage to RBAC-enabled version
Preserves existing keys and creates appropriate access permissions
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

from secure_storage import APIKeyStorage
from secure_storage_rbac import SecureKeyStorageRBAC
from rbac_models import RBACManager, Role, Permission


def migrate_storage(old_storage_path: str, new_storage_path: str, admin_password: str):
    """Migrate from old storage to RBAC-enabled storage"""
    
    print("Starting migration to RBAC-enabled storage...")
    
    # Initialize old storage
    try:
        old_storage = APIKeyStorage(storage_path=old_storage_path)
        print(f"✓ Loaded existing storage from {old_storage_path}")
    except Exception as e:
        print(f"✗ Failed to load existing storage: {e}")
        return False
    
    # Initialize new RBAC-enabled storage
    try:
        new_storage = SecureKeyStorageRBAC(
            storage_path=new_storage_path,
            rbac_db_path=os.path.join(new_storage_path, "rbac.db")
        )
        print(f"✓ Created new RBAC-enabled storage at {new_storage_path}")
    except Exception as e:
        print(f"✗ Failed to create new storage: {e}")
        return False
    
    # Update admin password if provided
    if admin_password:
        try:
            # Update the default admin password
            import sqlite3
            conn = sqlite3.connect(os.path.join(new_storage_path, "rbac.db"))
            cursor = conn.cursor()
            
            # Get admin user ID
            cursor.execute("SELECT id FROM users WHERE username = 'admin' AND role = ?", 
                         (Role.ADMIN.value,))
            admin_id = cursor.fetchone()
            
            if admin_id:
                # Update password
                from rbac_models import RBACManager
                rbac = RBACManager(os.path.join(new_storage_path, "rbac.db"))
                password_hash = rbac._hash_password(admin_password)
                
                cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                             (password_hash, admin_id[0]))
                conn.commit()
                print(f"✓ Updated admin password")
            
            conn.close()
        except Exception as e:
            print(f"⚠ Warning: Could not update admin password: {e}")
    
    # Create user mapping
    user_map = {}  # Maps old usernames to new user IDs
    users_created = {}  # Track created users
    
    # Migrate keys
    migrated_count = 0
    failed_count = 0
    
    for key_id, key_data in old_storage.keys_data.items():
        try:
            # Extract key information
            service = key_data.get("service", "unknown")
            api_key = key_data.get("api_key")
            username = key_data.get("user", "unknown")
            created_at = key_data.get("created_at")
            metadata = key_data.get("metadata", {})
            
            # Get or create user
            if username not in user_map:
                # Check if user exists
                import sqlite3
                conn = sqlite3.connect(os.path.join(new_storage_path, "rbac.db"))
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                existing_user = cursor.fetchone()
                conn.close()
                
                if existing_user:
                    user_map[username] = existing_user[0]
                else:
                    # Create user with default password (same as username)
                    # In production, you'd want to handle this differently
                    try:
                        user_id = new_storage.rbac.create_user(
                            username=username,
                            password=username,  # Default password = username
                            role=Role.USER,
                            metadata={"migrated": True, "migration_date": datetime.now().isoformat()}
                        )
                        user_map[username] = user_id
                        users_created[username] = user_id
                        print(f"  ✓ Created user '{username}' with USER role")
                    except Exception as e:
                        print(f"  ✗ Failed to create user '{username}': {e}")
                        continue
            
            user_id = user_map[username]
            
            # Add the key with proper ownership
            new_key_id = new_storage.add_api_key_with_rbac(
                service=service,
                api_key=api_key,
                user_id=user_id,
                metadata={
                    **metadata,
                    "migrated_from": key_id,
                    "migration_date": datetime.now().isoformat(),
                    "original_created_at": created_at
                }
            )
            
            # Preserve access statistics
            if key_data.get("last_accessed"):
                new_storage.keys_data[new_key_id]["last_accessed"] = key_data["last_accessed"]
            if key_data.get("access_count"):
                new_storage.keys_data[new_key_id]["access_count"] = key_data["access_count"]
            
            # Save changes
            new_storage._save_keys()
            
            migrated_count += 1
            print(f"  ✓ Migrated key '{service}' (owner: {username})")
            
        except Exception as e:
            failed_count += 1
            print(f"  ✗ Failed to migrate key {key_id}: {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print("Migration Summary:")
    print(f"  Keys migrated: {migrated_count}")
    print(f"  Keys failed: {failed_count}")
    print(f"  Users created: {len(users_created)}")
    
    if users_created:
        print("\nNew users created (password = username):")
        for username, user_id in users_created.items():
            print(f"  - {username} (ID: {user_id})")
        print("\n⚠ IMPORTANT: Ask these users to change their passwords!")
    
    print("\n✓ Migration completed!")
    
    # Create migration report
    report_path = os.path.join(new_storage_path, "migration_report.json")
    report = {
        "migration_date": datetime.now().isoformat(),
        "source_path": old_storage_path,
        "destination_path": new_storage_path,
        "keys_migrated": migrated_count,
        "keys_failed": failed_count,
        "users_created": users_created,
        "admin_password_updated": bool(admin_password)
    }
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nMigration report saved to: {report_path}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Migrate existing secure storage to RBAC-enabled version"
    )
    parser.add_argument(
        "--source",
        "-s",
        default="./keys",
        help="Path to existing storage directory (default: ./keys)"
    )
    parser.add_argument(
        "--destination",
        "-d",
        default="./keys_rbac",
        help="Path for new RBAC-enabled storage (default: ./keys_rbac)"
    )
    parser.add_argument(
        "--admin-password",
        "-p",
        help="Password for admin user (leave empty to keep default)"
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite destination if it exists"
    )
    
    args = parser.parse_args()
    
    # Validate source
    if not os.path.exists(args.source):
        print(f"Error: Source directory '{args.source}' does not exist")
        sys.exit(1)
    
    # Check destination
    if os.path.exists(args.destination) and not args.force:
        print(f"Error: Destination '{args.destination}' already exists. Use --force to overwrite")
        sys.exit(1)
    
    # Create destination directory
    os.makedirs(args.destination, exist_ok=True)
    
    # Run migration
    success = migrate_storage(args.source, args.destination, args.admin_password)
    
    if success:
        print("\n🎉 Migration successful!")
        print(f"\nNext steps:")
        print(f"1. Update your application to use the new storage path: {args.destination}")
        print(f"2. Update the dashboard backend to use main_rbac.py instead of main.py")
        print(f"3. Have users change their default passwords")
        print(f"4. Review and adjust user roles as needed")
        print(f"5. Test thoroughly before removing old storage")
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()