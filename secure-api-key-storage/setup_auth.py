#!/usr/bin/env python3
"""
Authentication System Setup Script

This script helps initialize the enhanced authentication system for the
Secure API Key Storage application.
"""

import os
import sys
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))

from auth_manager import AuthenticationManager
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
import getpass

console = Console()


def main():
    """Main setup function."""
    console.print(Panel(
        "[bold cyan]Secure API Key Storage - Authentication Setup[/bold cyan]\n\n"
        "This script will help you set up the enhanced authentication system.",
        title="Setup Wizard"
    ))
    
    # Initialize auth manager
    auth_manager = AuthenticationManager()
    
    # Check if any users exist
    try:
        existing_users = auth_manager.auth_manager._get_user_by_username("admin")
        if existing_users:
            console.print("[yellow]An admin user already exists.[/yellow]")
            if not Confirm.ask("Do you want to create another user?"):
                return
    except:
        pass
    
    console.print("\n[bold]Step 1: Create Administrator Account[/bold]")
    
    # Get admin credentials
    while True:
        username = Prompt.ask("Admin username", default="admin")
        password = getpass.getpass("Password (min 12 characters): ")
        
        if len(password) < 12:
            console.print("[red]Password must be at least 12 characters[/red]")
            continue
        
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            console.print("[red]Passwords do not match[/red]")
            continue
        
        break
    
    email = Prompt.ask("Email address (optional)", default="")
    enable_2fa = Confirm.ask("Enable two-factor authentication?", default=True)
    
    try:
        # Create admin user
        user = auth_manager.create_user(
            username=username,
            password=password,
            email=email if email else None,
            is_admin=True,
            require_2fa=enable_2fa
        )
        
        console.print(f"\n[green]✓ Admin user '{username}' created successfully[/green]")
        
        # Set up 2FA if enabled
        if enable_2fa:
            console.print("\n[bold]Step 2: Set Up Two-Factor Authentication[/bold]")
            
            tfa_data = auth_manager.setup_2fa(user['user_id'])
            
            console.print("\n[cyan]Scan this QR code with your authenticator app:[/cyan]")
            console.print(f"Secret key: [bold]{tfa_data['totp_secret']}[/bold]")
            
            # Save QR code
            qr_path = Path.home() / ".secure-keys" / f"admin_qr_code.png"
            qr_path.parent.mkdir(exist_ok=True)
            
            import base64
            with open(qr_path, 'wb') as f:
                f.write(base64.b64decode(tfa_data['qr_code']))
            
            console.print(f"\n[green]QR code saved to: {qr_path}[/green]")
            
            # Display backup codes
            console.print("\n[yellow]IMPORTANT: Save these backup codes in a secure location:[/yellow]")
            table = Table(title="Backup Codes", show_header=False)
            for i, code in enumerate(tfa_data['backup_codes'], 1):
                table.add_row(f"{i}.", code)
            console.print(table)
            
            # Verify 2FA setup
            console.print("\n[cyan]Enter a code from your authenticator to verify:[/cyan]")
            for attempt in range(3):
                code = Prompt.ask("Verification code")
                if auth_manager.verify_2fa(user['user_id'], code):
                    console.print("[green]✓ 2FA verified successfully[/green]")
                    break
                else:
                    console.print("[red]Invalid code, please try again[/red]")
        
        # Environment setup instructions
        console.print("\n[bold]Step 3: Environment Configuration[/bold]")
        console.print("\nAdd these to your environment variables or .env file:")
        console.print(f"[cyan]API_KEY_MASTER=[/cyan]{password}")
        console.print(f"[cyan]JWT_SECRET_KEY=[/cyan]{os.urandom(32).hex()}")
        
        # Integration instructions
        console.print("\n[bold]Integration Instructions:[/bold]")
        console.print("\n[yellow]CLI Usage:[/yellow]")
        console.print("1. Login: [cyan]secure-keys auth login[/cyan]")
        console.print("2. Register new user: [cyan]secure-keys auth register[/cyan]")
        console.print("3. Setup 2FA: [cyan]secure-keys auth setup-2fa[/cyan]")
        console.print("4. Setup certificate: [cyan]secure-keys auth setup-certificate[/cyan]")
        
        console.print("\n[yellow]Dashboard:[/yellow]")
        console.print("The dashboard backend now supports:")
        console.print("- User authentication with 2FA")
        console.print("- Certificate-based authentication")
        console.print("- Authentication audit logging")
        console.print("- Session management")
        
        console.print("\n[green]✓ Authentication system setup complete![/green]")
        
    except Exception as e:
        console.print(f"\n[red]Setup failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()