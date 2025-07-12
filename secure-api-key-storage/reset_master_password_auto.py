#!/usr/bin/env python3
"""
Automated Master Password Reset Script
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime

# Set the new master password here
NEW_MASTER_PASSWORD = "SecureApiKey2025!"

def backup_files(backup_dir):
    """Create backups of critical files before reset"""
    files_to_backup = [
        "keys/encrypted_keys.json",
        "dashboard/backend/.env",
        "dashboard.db",
        "rbac.db"
    ]
    
    print(f"Creating backup in {backup_dir}...")
    os.makedirs(backup_dir, exist_ok=True)
    
    for file in files_to_backup:
        if os.path.exists(file):
            backup_path = os.path.join(backup_dir, os.path.basename(file))
            shutil.copy2(file, backup_path)
            print(f"  Backed up: {file}")

def update_env_file(new_password):
    """Update the .env file with new master password"""
    env_path = "dashboard/backend/.env"
    env_backup = env_path + ".bak"
    
    # Create backup
    shutil.copy2(env_path, env_backup)
    
    # Read and update env file
    with open(env_path, 'r') as f:
        lines = f.readlines()
    
    updated_lines = []
    for line in lines:
        if line.startswith('API_KEY_MASTER='):
            updated_lines.append(f'API_KEY_MASTER={new_password}\n')
        elif line.startswith('MASTER_PASSWORD='):
            updated_lines.append(f'MASTER_PASSWORD={new_password}\n')
        else:
            updated_lines.append(line)
    
    # Add MASTER_PASSWORD if not present
    if not any(line.startswith('MASTER_PASSWORD=') for line in updated_lines):
        updated_lines.insert(2, f'MASTER_PASSWORD={new_password}\n')
    
    with open(env_path, 'w') as f:
        f.writelines(updated_lines)
    
    print(f"Updated {env_path}")

def clear_encrypted_keys():
    """Clear existing encrypted keys (they can't be decrypted with new password)"""
    keys_file = "keys/encrypted_keys.json"
    if os.path.exists(keys_file):
        # Keep the file structure but clear the keys
        empty_keys = {
            "keys": {},
            "metadata": {
                "version": "2.0",
                "reset_date": datetime.now().isoformat(),
                "reset_reason": "master_password_reset"
            }
        }
        with open(keys_file, 'w') as f:
            json.dump(empty_keys, f, indent=2)
        print(f"Cleared encrypted keys in {keys_file}")

def update_docker_env():
    """Create/update docker environment file"""
    docker_env = "../.env"
    with open(docker_env, 'w') as f:
        f.write(f"MASTER_PASSWORD={NEW_MASTER_PASSWORD}\n")
        f.write(f"API_KEY_MASTER={NEW_MASTER_PASSWORD}\n")
    print(f"Created {docker_env}")

def main():
    print("=== Secure API Key Storage - Master Password Reset (Automated) ===\n")
    
    print(f"Setting new master password: {NEW_MASTER_PASSWORD[:3]}{'*' * (len(NEW_MASTER_PASSWORD) - 3)}")
    print("")
    
    # Create backup
    backup_dir = f"backups/reset_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_files(backup_dir)
    
    # Update configurations
    update_env_file(NEW_MASTER_PASSWORD)
    clear_encrypted_keys()
    update_docker_env()
    
    print("\n=== Reset Complete ===")
    print("\nNew master password has been set.")
    print("\nNext steps:")
    print("1. Restart Docker services:")
    print("   cd .. && docker-compose down && docker-compose up -d")
    print("")
    print("2. Login to the web interface with the new password")
    print("   URL: http://localhost:3000")
    print(f"   Password: {NEW_MASTER_PASSWORD}")
    print("")
    print(f"3. Backup created in: {backup_dir}")
    print("")
    print("4. Re-add any API keys that were stored previously")

if __name__ == "__main__":
    main()