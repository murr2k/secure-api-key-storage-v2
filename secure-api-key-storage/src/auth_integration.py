"""
Authentication Integration Module

Bridges the enhanced authentication system with CLI and Dashboard components.
"""

import sys
import json
import getpass
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from functools import wraps
import click
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table

from .auth_manager import AuthenticationManager


console = Console()


class AuthIntegration:
    """Integrates authentication with CLI and dashboard."""

    def __init__(self):
        self.auth_manager = AuthenticationManager()
        self.session_file = Path.home() / ".secure-keys" / ".session"
        self.current_session = None

    def _save_session(self, session_data: Dict[str, str]):
        """Save session data to file."""
        self.session_file.parent.mkdir(exist_ok=True)
        with open(self.session_file, "w") as f:
            json.dump(session_data, f)
        # Secure file permissions
        self.session_file.chmod(0o600)

    def _load_session(self) -> Optional[Dict[str, str]]:
        """Load session data from file."""
        if not self.session_file.exists():
            return None

        try:
            with open(self.session_file, "r") as f:
                return json.load(f)
        except Exception:
            return None

    def _clear_session(self):
        """Clear stored session."""
        if self.session_file.exists():
            self.session_file.unlink()

    # CLI Authentication Methods

    def cli_login(
        self, username: Optional[str] = None, use_certificate: bool = False
    ) -> Dict[str, Any]:
        """Interactive CLI login."""
        console.print(Panel("[bold cyan]Secure Key Manager - Authentication[/bold cyan]"))

        try:
            if use_certificate:
                return self._cli_certificate_login()
            else:
                return self._cli_password_login(username)
        except Exception as e:
            console.print(f"[red]Authentication failed: {e}[/red]")
            raise

    def _cli_password_login(self, username: Optional[str] = None) -> Dict[str, Any]:
        """Password-based CLI login."""
        # Get credentials
        if not username:
            username = Prompt.ask("Username")

        password = getpass.getpass("Password: ")

        # Authenticate
        auth_result = self.auth_manager.authenticate_password(username, password)

        # Handle 2FA if required
        if auth_result.get("require_2fa") and auth_result.get("totp_configured"):
            console.print("[yellow]Two-factor authentication required[/yellow]")

            # Try TOTP first
            for attempt in range(3):
                totp_code = Prompt.ask("Enter 2FA code (or 'backup' to use backup code)")

                if totp_code.lower() == "backup":
                    backup_code = Prompt.ask("Enter backup code")
                    if self.auth_manager.verify_backup_code(auth_result["user_id"], backup_code):
                        console.print("[green]✓ Backup code verified[/green]")
                        break
                    else:
                        console.print("[red]Invalid backup code[/red]")
                else:
                    if self.auth_manager.verify_2fa(auth_result["user_id"], totp_code):
                        console.print("[green]✓ 2FA verified[/green]")
                        break
                    else:
                        console.print("[red]Invalid 2FA code[/red]")

                if attempt == 2:
                    raise ValueError("Too many failed 2FA attempts")

        # Create session
        session = self.auth_manager.create_session(auth_result["user_id"])
        self._save_session(session)

        console.print(f"[green]✓ Logged in as {username}[/green]")

        return {**auth_result, "session": session}

    def _cli_certificate_login(self) -> Dict[str, Any]:
        """Certificate-based CLI login."""
        cert_path = Prompt.ask("Path to client certificate")

        if not Path(cert_path).exists():
            raise ValueError("Certificate file not found")

        with open(cert_path, "r") as f:
            certificate_pem = f.read()

        # Authenticate
        auth_result = self.auth_manager.authenticate_certificate(certificate_pem)

        # Create session
        session = self.auth_manager.create_session(auth_result["user_id"])
        self._save_session(session)

        console.print(f"[green]✓ Logged in as {auth_result['username']} (certificate auth)[/green]")

        return {**auth_result, "session": session}

    def cli_logout(self):
        """CLI logout."""
        session = self._load_session()
        if session:
            self.auth_manager.invalidate_session(session["session_token"])
            self._clear_session()
            console.print("[green]✓ Logged out successfully[/green]")
        else:
            console.print("[yellow]Not logged in[/yellow]")

    def cli_register(self):
        """Interactive CLI user registration."""
        console.print(Panel("[bold cyan]Create New User Account[/bold cyan]"))

        # Get user details
        username = Prompt.ask("Username")
        email = Prompt.ask("Email (optional)", default="")

        # Get password
        while True:
            password = getpass.getpass("Password (min 12 characters): ")
            if len(password) < 12:
                console.print("[red]Password must be at least 12 characters[/red]")
                continue

            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                console.print("[red]Passwords do not match[/red]")
                continue

            break

        # Ask about 2FA
        require_2fa = Confirm.ask("Enable two-factor authentication?", default=True)

        try:
            # Create user
            user = self.auth_manager.create_user(
                username=username,
                password=password,
                email=email if email else None,
                require_2fa=require_2fa,
            )

            console.print(f"[green]✓ User '{username}' created successfully[/green]")

            # Set up 2FA if enabled
            if require_2fa:
                self._cli_setup_2fa(user["user_id"])

        except Exception as e:
            console.print(f"[red]Failed to create user: {e}[/red]")
            raise

    def _cli_setup_2fa(self, user_id: int):
        """CLI 2FA setup."""
        console.print("\n[yellow]Setting up two-factor authentication...[/yellow]")

        # Generate 2FA
        tfa_data = self.auth_manager.setup_2fa(user_id)

        # Display QR code info
        console.print("\n[cyan]Scan this QR code with your authenticator app:[/cyan]")
        console.print(f"Secret key: [bold]{tfa_data['totp_secret']}[/bold]")

        # Save QR code if requested
        if Confirm.ask("Save QR code to file?"):
            qr_path = Path.home() / ".secure-keys" / f"qr_code_{user_id}.png"
            import base64

            with open(qr_path, "wb") as f:
                f.write(base64.b64decode(tfa_data["qr_code"]))
            console.print(f"[green]QR code saved to: {qr_path}[/green]")

        # Display backup codes
        console.print("\n[yellow]Backup codes (save these in a secure location):[/yellow]")
        table = Table(show_header=False)
        for i, code in enumerate(tfa_data["backup_codes"], 1):
            table.add_row(f"{i}.", code)
        console.print(table)

        # Verify setup
        console.print("\n[cyan]Enter a code from your authenticator app to verify setup:[/cyan]")
        for attempt in range(3):
            code = Prompt.ask("Verification code")
            if self.auth_manager.verify_2fa(user_id, code):
                console.print("[green]✓ 2FA setup completed successfully[/green]")
                break
            else:
                console.print("[red]Invalid code, please try again[/red]")
                if attempt == 2:
                    console.print("[red]Setup failed - too many invalid attempts[/red]")

    def cli_setup_certificate(self):
        """CLI certificate setup."""
        # Check if logged in
        session = self._load_session()
        if not session:
            console.print("[red]Please login first[/red]")
            return

        # Validate session
        session_data = self.auth_manager.validate_session(session["session_token"])
        if not session_data:
            console.print("[red]Session expired, please login again[/red]")
            self._clear_session()
            return

        console.print(Panel("[bold cyan]Set Up Certificate Authentication[/bold cyan]"))

        cert_path = Prompt.ask("Path to client certificate (PEM format)")

        if not Path(cert_path).exists():
            console.print("[red]Certificate file not found[/red]")
            return

        try:
            with open(cert_path, "r") as f:
                certificate_pem = f.read()

            cert_info = self.auth_manager.setup_certificate_auth(
                session_data["user_id"], certificate_pem
            )

            console.print("[green]✓ Certificate authentication configured[/green]")
            console.print(f"Subject: {cert_info['subject']}")
            console.print(f"Fingerprint: {cert_info['fingerprint']}")
            console.print(f"Valid until: {cert_info['not_after']}")

        except Exception as e:
            console.print(f"[red]Failed to set up certificate: {e}[/red]")

    # CLI Decorator for Authentication

    def require_auth(self, require_admin: bool = False):
        """Decorator to require authentication for CLI commands."""

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Load session
                session = self._load_session()
                if not session:
                    console.print("[red]Authentication required. Please login first.[/red]")
                    console.print("Use: secure-keys auth login")
                    sys.exit(1)

                # Validate session
                session_data = self.auth_manager.validate_session(session["session_token"])
                if not session_data:
                    console.print("[red]Session expired. Please login again.[/red]")
                    self._clear_session()
                    sys.exit(1)

                # Check admin requirement
                if require_admin and not session_data.get("is_admin"):
                    console.print("[red]This command requires administrator privileges.[/red]")
                    sys.exit(1)

                # Add session data to context
                if isinstance(args[0], click.Context):
                    args[0].obj = args[0].obj or {}
                    args[0].obj["session"] = session_data

                return func(*args, **kwargs)

            return wrapper

        return decorator

    # Dashboard Integration Methods

    def create_dashboard_auth_routes(self, auth_module):
        """Create enhanced authentication routes for the dashboard."""
        from fastapi import Depends, HTTPException, status, Request
        from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
        from pydantic import BaseModel

        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

        class LoginRequest(BaseModel):
            username: str
            password: str
            totp_code: Optional[str] = None
            use_backup_code: bool = False

        class RegisterRequest(BaseModel):
            username: str
            password: str
            email: Optional[str] = None
            enable_2fa: bool = True

        class Setup2FAResponse(BaseModel):
            qr_code: str
            backup_codes: list[str]

        class CertificateSetupRequest(BaseModel):
            certificate_pem: str

        # Enhanced get_current_user dependency
        async def get_current_user(token: str = Depends(oauth2_scheme), request: Request = None):
            """Get current user from JWT token."""
            user_data = self.auth_manager.validate_jwt_token(token)
            if not user_data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Add request info for audit logging
            if request:
                ip_address = request.client.host if request.client else None
                user_agent = request.headers.get("User-Agent")
                user_data["ip_address"] = ip_address
                user_data["user_agent"] = user_agent

            return user_data

        # Replace the existing auth module functions
        auth_module.get_current_user = get_current_user

        # New login endpoint with 2FA support
        async def enhanced_login(
            form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None
        ):
            """Enhanced login with 2FA support."""
            ip_address = request.client.host if request and request.client else None

            try:
                # Authenticate with password
                auth_result = self.auth_manager.authenticate_password(
                    form_data.username, form_data.password, ip_address
                )

                # Create session
                session = self.auth_manager.create_session(
                    auth_result["user_id"],
                    ip_address=ip_address,
                    user_agent=request.headers.get("User-Agent") if request else None,
                )

                # Return tokens (2FA verification will be handled separately if needed)
                return {
                    "access_token": session["access_token"],
                    "refresh_token": session["refresh_token"],
                    "token_type": "bearer",
                    "require_2fa": auth_result.get("require_2fa", False)
                    and auth_result.get("totp_configured", False),
                }

            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(e),
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # 2FA verification endpoint
        async def verify_2fa(totp_code: str, user: dict = Depends(get_current_user)):
            """Verify 2FA code."""
            if self.auth_manager.verify_2fa(user["user_id"], totp_code):
                # Create new session with 2FA verified
                session = self.auth_manager.create_session(
                    user["user_id"],
                    ip_address=user.get("ip_address"),
                    user_agent=user.get("user_agent"),
                )

                return {
                    "access_token": session["access_token"],
                    "refresh_token": session["refresh_token"],
                    "token_type": "bearer",
                    "verified": True,
                }
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code"
                )

        # User registration endpoint
        async def register_user(request: RegisterRequest):
            """Register a new user."""
            try:
                user = self.auth_manager.create_user(
                    username=request.username,
                    password=request.password,
                    email=request.email,
                    require_2fa=request.enable_2fa,
                )

                return {
                    "message": "User created successfully",
                    "user_id": user["user_id"],
                    "require_2fa_setup": request.enable_2fa,
                }

            except Exception as e:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        # 2FA setup endpoint
        async def setup_2fa(user: dict = Depends(get_current_user)) -> Setup2FAResponse:
            """Set up 2FA for current user."""
            try:
                tfa_data = self.auth_manager.setup_2fa(user["user_id"])

                return Setup2FAResponse(
                    qr_code=tfa_data["qr_code"], backup_codes=tfa_data["backup_codes"]
                )

            except Exception as e:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        # Certificate setup endpoint
        async def setup_certificate(
            request: CertificateSetupRequest, user: dict = Depends(get_current_user)
        ):
            """Set up certificate authentication."""
            try:
                cert_info = self.auth_manager.setup_certificate_auth(
                    user["user_id"], request.certificate_pem
                )

                return {"message": "Certificate authentication configured", **cert_info}

            except Exception as e:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        # Audit log endpoint
        async def get_auth_audit_logs(limit: int = 100, user: dict = Depends(get_current_user)):
            """Get authentication audit logs."""
            if not user.get("is_admin"):
                # Regular users can only see their own logs
                logs = self.auth_manager.get_audit_logs(user["user_id"], limit)
            else:
                # Admins can see all logs
                logs = self.auth_manager.get_audit_logs(limit=limit)

            return logs

        return {
            "login": enhanced_login,
            "verify_2fa": verify_2fa,
            "register": register_user,
            "setup_2fa": setup_2fa,
            "setup_certificate": setup_certificate,
            "get_audit_logs": get_auth_audit_logs,
            "get_current_user": get_current_user,
        }


# Global instance
auth_integration = AuthIntegration()
