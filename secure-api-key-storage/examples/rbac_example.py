#!/usr/bin/env python3
"""
Example: Using the RBAC-enabled Secure API Key Storage
Demonstrates common usage patterns for the RBAC system
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from rbac_models import Role, Permission
from secure_storage_rbac import SecureKeyStorageRBAC


def main():
    """Example usage of RBAC-enabled storage"""
    
    print("RBAC-Enabled Secure API Key Storage Example")
    print("=" * 50)
    
    # Initialize storage with RBAC
    storage = SecureKeyStorageRBAC(
        storage_path="./example_keys",
        master_password="example_master_password",
        rbac_db_path="./example_keys/rbac.db"
    )
    
    # 1. Create users for your team
    print("\n1. Creating team members...")
    
    # Team lead (admin)
    lead_id = storage.rbac.create_user(
        username="alice_lead",
        password="alice_secure_pass",
        role=Role.ADMIN,
        email="alice@company.com"
    )
    print(f"✓ Created team lead Alice (admin)")
    
    # Developer (user)
    dev_id = storage.rbac.create_user(
        username="bob_dev",
        password="bob_secure_pass",
        role=Role.USER,
        email="bob@company.com"
    )
    print(f"✓ Created developer Bob (user)")
    
    # QA tester (viewer)
    qa_id = storage.rbac.create_user(
        username="charlie_qa",
        password="charlie_secure_pass",
        role=Role.VIEWER,
        email="charlie@company.com"
    )
    print(f"✓ Created QA tester Charlie (viewer)")
    
    # 2. Store API keys with proper ownership
    print("\n2. Storing API keys...")
    
    # Alice stores production database key
    prod_db_key = storage.add_api_key_with_rbac(
        service="production_database",
        api_key="prod_db_secret_key_xyz789",
        user_id=lead_id,
        metadata={
            "description": "Production PostgreSQL database",
            "environment": "production",
            "critical": True
        }
    )
    print(f"✓ Alice stored production database key")
    
    # Bob stores development API key
    dev_api_key = storage.add_api_key_with_rbac(
        service="stripe_dev",
        api_key="sk_test_abc123def456",
        user_id=dev_id,
        metadata={
            "description": "Stripe test API key",
            "environment": "development"
        }
    )
    print(f"✓ Bob stored development API key")
    
    # 3. Share keys with appropriate permissions
    print("\n3. Sharing keys with team members...")
    
    # Alice shares prod DB key with Bob (read-only for emergencies)
    storage.grant_key_access(
        key_id=prod_db_key,
        granting_user_id=lead_id,
        target_user_id=dev_id,
        permissions=[Permission.KEY_READ],
        expires_at=datetime.now() + timedelta(days=30)
    )
    print(f"✓ Alice shared prod DB key with Bob (read-only, 30 days)")
    
    # Bob shares dev API key with Charlie for testing
    storage.grant_key_access(
        key_id=dev_api_key,
        granting_user_id=dev_id,
        target_user_id=qa_id,
        permissions=[Permission.KEY_READ]
    )
    print(f"✓ Bob shared dev API key with Charlie (read-only)")
    
    # 4. Access keys based on permissions
    print("\n4. Accessing keys with permission checks...")
    
    # Bob tries to read the prod DB key (should work - has read permission)
    try:
        key_value = storage.get_api_key_with_rbac(prod_db_key, dev_id)
        print(f"✓ Bob successfully read prod DB key: {key_value[:10]}...")
    except Exception as e:
        print(f"✗ Bob couldn't read prod DB key: {e}")
    
    # Charlie tries to read the dev API key (should work)
    try:
        key_value = storage.get_api_key_with_rbac(dev_api_key, qa_id)
        print(f"✓ Charlie successfully read dev API key: {key_value[:10]}...")
    except Exception as e:
        print(f"✗ Charlie couldn't read dev API key: {e}")
    
    # Charlie tries to update the dev API key (should fail - no update permission)
    try:
        storage.update_api_key_with_rbac(dev_api_key, "new_value", qa_id)
        print(f"✗ Charlie shouldn't be able to update keys!")
    except Exception as e:
        print(f"✓ Charlie correctly denied update permission")
    
    # 5. List accessible keys for each user
    print("\n5. Listing accessible keys by user...")
    
    # Alice can see all keys (admin)
    alice_keys = storage.list_keys_with_rbac(lead_id)
    print(f"\nAlice (admin) can see {len(alice_keys)} keys:")
    for key in alice_keys:
        print(f"  - {key['service']} (owner: {key['user']})")
    
    # Bob can see his own keys + shared keys
    bob_keys = storage.list_keys_with_rbac(dev_id)
    print(f"\nBob (user) can see {len(bob_keys)} keys:")
    for key in bob_keys:
        print(f"  - {key['service']} (owner: {key['user']})")
    
    # Charlie can only see shared keys
    charlie_keys = storage.list_keys_with_rbac(qa_id)
    print(f"\nCharlie (viewer) can see {len(charlie_keys)} keys:")
    for key in charlie_keys:
        print(f"  - {key['service']} (owner: {key['user']})")
    
    # 6. Audit trail
    print("\n6. Reviewing audit logs...")
    
    # Get recent audit entries
    audit_logs = storage.rbac.get_audit_logs(limit=10)
    print(f"\nRecent activities ({len(audit_logs)} entries):")
    for log in audit_logs[:5]:
        action = log['action']
        user = log['username'] or f"user_{log['user_id']}"
        resource = log['resource_id'] or "system"
        print(f"  - {log['timestamp']}: {user} -> {action} on {resource}")
    
    # 7. Key rotation with permission check
    print("\n7. Key rotation example...")
    
    # Bob rotates his dev API key
    try:
        success = storage.rotate_key_with_rbac(
            key_id=dev_api_key,
            new_api_key="sk_test_new789xyz123",
            user_id=dev_id
        )
        print(f"✓ Bob successfully rotated his dev API key")
    except Exception as e:
        print(f"✗ Bob failed to rotate key: {e}")
    
    # 8. Clean up example
    print("\n8. Cleaning up...")
    
    # Revoke permissions
    storage.revoke_key_access(prod_db_key, lead_id, dev_id)
    print(f"✓ Revoked Bob's access to prod DB key")
    
    # Delete keys
    storage.revoke_key_with_rbac(prod_db_key, lead_id)
    storage.revoke_key_with_rbac(dev_api_key, dev_id)
    print(f"✓ Deleted example keys")
    
    print("\n" + "=" * 50)
    print("Example completed successfully!")
    print("\nKey takeaways:")
    print("- Users have role-based permissions")
    print("- Keys can be shared with specific permissions")
    print("- All actions are audited")
    print("- Access can be time-limited")
    print("- Admins have full visibility and control")


if __name__ == "__main__":
    main()
    
    # Clean up example directory
    import shutil
    if os.path.exists("./example_keys"):
        shutil.rmtree("./example_keys")
        print("\n✓ Cleaned up example directory")