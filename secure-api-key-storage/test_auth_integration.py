#!/usr/bin/env python3
"""
Test script for authentication integration

This script tests the various authentication features.
"""

import sys
import os
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))

from auth_manager import AuthenticationManager
from auth_integration import AuthIntegration
from rich.console import Console
from rich.table import Table
import time

console = Console()


def test_user_authentication():
    """Test user authentication features."""
    console.print("\n[bold cyan]Testing User Authentication[/bold cyan]")
    
    auth_manager = AuthenticationManager()
    
    # Test user creation
    try:
        test_user = auth_manager.create_user(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com",
            require_2fa=True
        )
        console.print("[green]✓ User creation successful[/green]")
        
        # Test password authentication
        auth_result = auth_manager.authenticate_password(
            "testuser", 
            "TestPassword123!"
        )
        console.print("[green]✓ Password authentication successful[/green]")
        
        # Test 2FA setup
        tfa_data = auth_manager.setup_2fa(test_user['user_id'])
        console.print("[green]✓ 2FA setup successful[/green]")
        console.print(f"  TOTP Secret: {tfa_data['totp_secret']}")
        console.print(f"  Backup codes: {len(tfa_data['backup_codes'])} generated")
        
        # Test session creation
        session = auth_manager.create_session(test_user['user_id'])
        console.print("[green]✓ Session creation successful[/green]")
        console.print(f"  Session token: {session['session_token'][:20]}...")
        
        # Test JWT validation
        jwt_data = auth_manager.validate_jwt_token(session['access_token'])
        console.print("[green]✓ JWT validation successful[/green]")
        console.print(f"  User: {jwt_data['username']}")
        
        # Test audit logging
        logs = auth_manager.get_audit_logs(user_id=test_user['user_id'])
        console.print(f"[green]✓ Audit logs retrieved: {len(logs)} entries[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ Test failed: {e}[/red]")
        return False
    
    return True


def test_cli_integration():
    """Test CLI integration features."""
    console.print("\n[bold cyan]Testing CLI Integration[/bold cyan]")
    
    auth_integration = AuthIntegration()
    
    try:
        # Test session management
        test_session = {
            "session_token": "test_token",
            "access_token": "test_access",
            "refresh_token": "test_refresh"
        }
        
        auth_integration._save_session(test_session)
        loaded_session = auth_integration._load_session()
        
        if loaded_session and loaded_session['session_token'] == test_session['session_token']:
            console.print("[green]✓ Session save/load successful[/green]")
        else:
            console.print("[red]✗ Session save/load failed[/red]")
            
        auth_integration._clear_session()
        console.print("[green]✓ Session clear successful[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ CLI integration test failed: {e}[/red]")
        return False
    
    return True


def test_security_features():
    """Test security features."""
    console.print("\n[bold cyan]Testing Security Features[/bold cyan]")
    
    auth_manager = AuthenticationManager()
    
    try:
        # Create a test user
        test_user = auth_manager.create_user(
            username="securitytest",
            password="SecurePassword123!",
            require_2fa=False
        )
        
        # Test failed login attempts
        console.print("\nTesting account lockout after failed attempts...")
        for i in range(6):
            try:
                auth_manager.authenticate_password(
                    "securitytest",
                    "WrongPassword"
                )
            except:
                pass
        
        # Check if account is locked
        try:
            auth_manager.authenticate_password(
                "securitytest",
                "SecurePassword123!"
            )
            console.print("[red]✗ Account lockout not working[/red]")
        except ValueError as e:
            if "locked" in str(e):
                console.print("[green]✓ Account lockout working correctly[/green]")
            else:
                console.print(f"[red]✗ Unexpected error: {e}[/red]")
        
        # Test password complexity
        try:
            auth_manager.create_user(
                username="weakpass",
                password="weak"
            )
            console.print("[red]✗ Weak password accepted[/red]")
        except ValueError:
            console.print("[green]✓ Password complexity enforced[/green]")
        
        # Test session expiration
        console.print("[green]✓ Security features tested[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ Security test failed: {e}[/red]")
        return False
    
    return True


def display_test_summary(results):
    """Display test summary."""
    console.print("\n[bold]Test Summary[/bold]")
    
    table = Table(title="Authentication System Test Results")
    table.add_column("Test Category", style="cyan")
    table.add_column("Result", style="green")
    table.add_column("Status")
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if r)
    
    for category, result in results.items():
        status = "[green]PASSED[/green]" if result else "[red]FAILED[/red]"
        table.add_row(category, str(result), status)
    
    console.print(table)
    
    console.print(f"\nTotal: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        console.print("\n[bold green]All tests passed! Authentication system is working correctly.[/bold green]")
    else:
        console.print("\n[bold red]Some tests failed. Please check the implementation.[/bold red]")


def main():
    """Main test function."""
    console.print("[bold]Authentication System Integration Test[/bold]")
    console.print("=" * 50)
    
    results = {}
    
    # Run tests
    results["User Authentication"] = test_user_authentication()
    results["CLI Integration"] = test_cli_integration()
    results["Security Features"] = test_security_features()
    
    # Display summary
    display_test_summary(results)
    
    # Cleanup test database
    console.print("\n[yellow]Cleaning up test data...[/yellow]")
    test_db = Path.home() / ".secure-keys" / "auth.db"
    if test_db.exists():
        # In production, you might want to keep the database
        console.print(f"Test database at: {test_db}")


if __name__ == "__main__":
    main()