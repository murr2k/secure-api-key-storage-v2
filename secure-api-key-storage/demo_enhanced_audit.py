#!/usr/bin/env python3
"""
Demo script for Enhanced Audit System with Tamper-Proofing and Rotation Enforcement

This script demonstrates:
1. Tamper-proof audit logging with cryptographic signatures
2. Automatic key rotation policy enforcement
3. Security event monitoring and alerting
4. Audit log integrity verification
"""

import os
import sys
import time
import json
from datetime import datetime, timedelta

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from secure_storage import APIKeyStorage
from audit_enhancement import (
    TamperProofAuditLogger, RotationPolicyEnforcer, SecurityEventMonitor,
    EventType, EventSeverity, RetentionPolicy, RotationPolicy
)
from monitoring_config import MonitoringConfiguration, SecurityEventHandler


def print_section(title: str):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}\n")


def demo_enhanced_audit():
    """Demonstrate enhanced audit system features"""
    
    print_section("Enhanced Audit System Demo")
    
    # 1. Initialize system with enhanced audit
    print("1. Initializing secure storage with enhanced audit system...")
    
    # Configure retention and rotation policies
    retention_policy = RetentionPolicy(
        default_retention_days=365,
        severity_retention={
            EventSeverity.DEBUG: 7,
            EventSeverity.INFO: 30,
            EventSeverity.WARNING: 90,
            EventSeverity.ERROR: 180,
            EventSeverity.CRITICAL: 730  # 2 years
        },
        archive_after_days=90,
        compress_archives=True
    )
    
    rotation_policy = RotationPolicy(
        max_key_age_days=90,
        warning_before_days=14,
        enforce_rotation=True,
        auto_rotate=False,
        block_expired_keys=True,
        grace_period_days=7,
        exempt_services=["legacy_system"]
    )
    
    # Initialize storage with enhanced audit
    storage = APIKeyStorage(
        storage_path="./demo_keys",
        master_password="demo_password_123",
        enable_enhanced_audit=True,
        retention_policy=retention_policy,
        rotation_policy=rotation_policy
    )
    
    print("✓ Storage initialized with enhanced audit system")
    print(f"  - Retention policy: {retention_policy.default_retention_days} days default")
    print(f"  - Rotation policy: {rotation_policy.max_key_age_days} days max age")
    print(f"  - Tamper-proof logging: Enabled")
    
    # 2. Add some API keys
    print_section("2. Adding API Keys with Audit Logging")
    
    keys = [
        ("github", "ghp_demo123456789", "alice"),
        ("openai", "sk-demo987654321", "bob"),
        ("aws", "AKIADEMO123456", "charlie")
    ]
    
    key_ids = []
    for service, api_key, user in keys:
        key_id = storage.add_api_key(
            service=service,
            api_key=api_key,
            user=user,
            metadata={"environment": "production"}
        )
        key_ids.append(key_id)
        print(f"✓ Added key for {service} (ID: {key_id})")
    
    # 3. Simulate key accesses
    print_section("3. Simulating Key Accesses")
    
    # Normal access
    for i, (key_id, (service, _, user)) in enumerate(zip(key_ids, keys)):
        retrieved = storage.get_api_key(key_id, user)
        if retrieved:
            print(f"✓ User {user} accessed {service} key")
    
    # Failed access attempts
    print("\nSimulating failed access attempts...")
    for i in range(3):
        storage.get_api_key("invalid_key_id", "hacker")
        print(f"✗ Failed access attempt {i+1}")
    
    # 4. Verify audit log integrity
    print_section("4. Verifying Audit Log Integrity")
    
    is_valid, issues = storage.verify_audit_integrity()
    
    if is_valid:
        print("✓ Audit log integrity verified - No tampering detected")
        print("  - All event hashes valid")
        print("  - All signatures verified")
        print("  - Hash chain intact")
    else:
        print("✗ Integrity check failed!")
        for issue in issues[:5]:  # Show first 5 issues
            print(f"  - {issue}")
    
    # 5. Test rotation policy enforcement
    print_section("5. Testing Rotation Policy Enforcement")
    
    # Simulate an old key
    if storage.rotation_enforcer:
        # Register a key as if it was created 100 days ago
        old_key_id = "old_test_key"
        old_date = datetime.utcnow() - timedelta(days=100)
        
        storage.rotation_enforcer.register_key(old_key_id, "test_service", old_date)
        print(f"✓ Registered old key (created {100} days ago)")
        
        # Check key validity
        is_valid, message = storage.rotation_enforcer.check_key_validity(old_key_id)
        print(f"\nKey validity check:")
        print(f"  - Valid: {is_valid}")
        print(f"  - Message: {message}")
        
        # Get rotation status
        rotation_status = storage.rotation_enforcer.get_rotation_status()
        print(f"\nRotation enforcement status:")
        print(f"  - Total keys tracked: {rotation_status['total_keys']}")
        print(f"  - Overdue keys: {rotation_status['overdue_keys']}")
        print(f"  - Blocked keys: {rotation_status['blocked_keys']}")
    
    # 6. Generate security reports
    print_section("6. Security Status and Reports")
    
    # Get comprehensive security status
    security_status = storage.get_security_status()
    
    print("Security Status Overview:")
    print(f"  - Enhanced audit enabled: {security_status['enhanced_audit_enabled']}")
    print(f"  - Total keys: {security_status['total_keys']}")
    print(f"  - Active keys: {security_status['active_keys']}")
    print(f"  - Expired keys: {security_status['expired_keys']}")
    
    if 'audit_integrity' in security_status:
        print(f"\nAudit Integrity:")
        print(f"  - Valid: {security_status['audit_integrity']['valid']}")
        print(f"  - Issues: {security_status['audit_integrity']['issues_count']}")
    
    if 'rotation_enforcement' in security_status:
        print(f"\nRotation Enforcement:")
        enforcement = security_status['rotation_enforcement']
        print(f"  - Policy max age: {enforcement['policy']['max_age_days']} days")
        print(f"  - Warning period: {enforcement['policy']['warning_days']} days")
        print(f"  - Auto-rotate: {enforcement['policy']['auto_rotate']}")
    
    # 7. Test monitoring and alerting
    print_section("7. Monitoring and Alerting Configuration")
    
    # Generate monitoring configuration
    monitoring_config = MonitoringConfiguration()
    
    print("Generated monitoring configuration:")
    print(f"  - Alert rules: {len(monitoring_config.alert_rules)}")
    print(f"  - Dashboards: {len(monitoring_config.grafana_dashboards)}")
    
    # Save monitoring configs
    monitoring_config.save_configurations("./demo_monitoring")
    print("\n✓ Monitoring configurations saved to ./demo_monitoring/")
    
    # 8. Simulate security incident
    print_section("8. Security Incident Simulation")
    
    # Create incident handler
    incident_handler = SecurityEventHandler(monitoring_config)
    
    # Simulate tampering detection
    if storage.enhanced_audit:
        # Log a critical event
        storage.enhanced_audit.log_event(
            EventType.TAMPERING_DETECTED,
            EventSeverity.CRITICAL,
            "system",
            details={
                "detection_method": "hash_mismatch",
                "affected_events": 5,
                "first_tampering": datetime.utcnow().isoformat()
            }
        )
        
        print("✓ Simulated tampering detection event")
        
        # Handle the incident
        incident = incident_handler.handle_critical_event(
            "tampering_detected",
            {
                "affected_logs": 5,
                "detection_method": "signature_verification_failure",
                "suspected_tampering_time": datetime.utcnow().isoformat()
            }
        )
        
        print(f"\nIncident Response:")
        print(f"  - Incident ID: {incident['id']}")
        print(f"  - Status: {incident['status']}")
        print(f"  - Actions taken:")
        for action in incident['actions_taken']:
            print(f"    • {action}")
    
    # 9. Generate audit report
    print_section("9. Audit Report Generation")
    
    audit_report = storage.get_audit_report(days=1)
    
    print("Audit Report Summary:")
    print(f"  - Period: {audit_report['period_days']} days")
    print(f"  - Generated at: {audit_report['generated_at']}")
    
    if 'statistics' in audit_report:
        stats = audit_report['statistics']
        print(f"\nStatistics:")
        print(f"  - Total accesses: {stats['total_accesses']}")
        print(f"  - Keys rotated: {stats['keys_rotated']}")
        print(f"  - Keys revoked: {stats['keys_revoked']}")
    
    if 'security_summary' in audit_report:
        summary = audit_report['security_summary']
        print(f"\nSecurity Summary:")
        print(f"  - Active alerts: {summary.get('active_alerts', 0)}")
        print(f"  - Event types: {len(summary.get('event_counts', []))}")
    
    # 10. Enforce retention policies
    print_section("10. Retention Policy Enforcement")
    
    print("Enforcing retention policies...")
    storage.enforce_retention_policies()
    print("✓ Retention policies enforced")
    print("  - Old events archived/deleted according to policy")
    print("  - Audit logs compressed and stored")
    
    # Cleanup
    print_section("Demo Complete!")
    
    print("Key features demonstrated:")
    print("  ✓ Tamper-proof audit logging with cryptographic signatures")
    print("  ✓ Automatic key rotation policy enforcement")
    print("  ✓ Security event monitoring and alerting")
    print("  ✓ Audit log integrity verification")
    print("  ✓ Comprehensive security reporting")
    print("  ✓ Incident response handling")
    print("  ✓ Retention policy enforcement")
    
    print("\nGenerated files:")
    print("  - Audit logs: ./demo_keys/audit/")
    print("  - Monitoring configs: ./demo_monitoring/")
    print("  - Traditional audit log: ./demo_keys/audit.log")


def demo_tampering_detection():
    """Demonstrate tamper detection capabilities"""
    
    print_section("Tamper Detection Demo")
    
    print("This demo shows how the system detects audit log tampering...")
    
    # Initialize system
    storage = APIKeyStorage(
        storage_path="./tamper_demo",
        master_password="demo_password",
        enable_enhanced_audit=True
    )
    
    # Add a key and access it
    key_id = storage.add_api_key("test_service", "test_key_123", "alice")
    storage.get_api_key(key_id, "alice")
    
    print("✓ Created audit events")
    
    # Verify integrity (should pass)
    is_valid, issues = storage.verify_audit_integrity()
    print(f"\nInitial integrity check: {'PASSED' if is_valid else 'FAILED'}")
    
    # Simulate tampering (DO NOT DO THIS IN PRODUCTION!)
    if storage.enhanced_audit:
        audit_db = storage.enhanced_audit.db_path
        
        print("\n⚠️  Simulating tampering (for demo only)...")
        
        import sqlite3
        conn = sqlite3.connect(audit_db)
        
        # Modify an audit event
        conn.execute("""
            UPDATE audit_events 
            SET details = '{"tampered": true}'
            WHERE event_type = 'key_accessed'
            LIMIT 1
        """)
        conn.commit()
        conn.close()
        
        print("✓ Tampered with audit log")
        
        # Verify integrity again (should fail)
        is_valid, issues = storage.verify_audit_integrity()
        print(f"\nPost-tampering integrity check: {'PASSED' if is_valid else 'FAILED'}")
        
        if not is_valid:
            print("\n✓ Tampering detected!")
            print("Issues found:")
            for issue in issues[:3]:
                print(f"  - {issue}")


if __name__ == "__main__":
    try:
        # Run main demo
        demo_enhanced_audit()
        
        # Optionally run tampering detection demo
        print("\n" + "="*60)
        response = input("\nRun tampering detection demo? (y/n): ")
        if response.lower() == 'y':
            demo_tampering_detection()
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup demo directories
        import shutil
        for dir_path in ["./demo_keys", "./demo_monitoring", "./tamper_demo"]:
            if os.path.exists(dir_path):
                try:
                    shutil.rmtree(dir_path)
                    print(f"\nCleaned up {dir_path}")
                except:
                    pass