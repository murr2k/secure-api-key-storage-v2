#!/usr/bin/env python3
"""
Reset Master Password Script
This script safely resets the master password for the secure API key storage system.
"""

import os
import sys
import getpass
import json
import shutil
from pathlib import Path
from datetime import datetime

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

def update_docker_compose():
    """Update docker-compose.yml with new password"""
    compose_path = "../docker-compose.yml"
    if os.path.exists(compose_path):
        compose_backup = compose_path + ".bak"
        shutil.copy2(compose_path, compose_backup)
        
        with open(compose_path, 'r') as f:
            content = f.read()
        
        # Update MASTER_PASSWORD in docker-compose
        import re
        content = re.sub(
            r'MASTER_PASSWORD:.*', 
            f'MASTER_PASSWORD: "${{MASTER_PASSWORD:-{new_password}}}"',
            content
        )
        
        with open(compose_path, 'w') as f:
            f.write(content)
        
        print(f"Updated {compose_path}")

def main():
    print("=== Secure API Key Storage - Master Password Reset ===\n")
    
    print("WARNING: This will:")
    print("1. Reset the master password")
    print("2. Clear all encrypted API keys (they cannot be recovered)")
    print("3. Require restart of all services")
    print("")
    
    confirm = input("Are you sure you want to continue? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Reset cancelled.")
        return
    
    # Get new password
    while True:
        password1 = getpass.getpass("Enter new master password: ")
        password2 = getpass.getpass("Confirm new master password: ")
        
        if password1 != password2:
            print("Passwords don't match. Try again.")
            continue
            
        if len(password1) < 8:
            print("Password must be at least 8 characters. Try again.")
            continue
            
        break
    
    new_password = password1
    
    # Create backup
    backup_dir = f"backups/reset_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_files(backup_dir)
    
    # Update configurations
    update_env_file(new_password)
    clear_encrypted_keys()
    
    # Create a .env file in the root if it doesn't exist
    root_env = "../.env"
    with open(root_env, 'w') as f:
        f.write(f"MASTER_PASSWORD={new_password}\n")
        f.write(f"API_KEY_MASTER={new_password}\n")
    print(f"Created {root_env}")
    
    print("\n=== Reset Complete ===")
    print("\nNext steps:")
    print("1. Restart all Docker services:")
    print("   docker-compose down && docker-compose up -d")
    print("")
    print("2. Re-add your API keys through the web interface")
    print("")
    print(f"3. Backup created in: {backup_dir}")
    print("")
    print("The new master password has been set successfully.")

if __name__ == "__main__":
    main()