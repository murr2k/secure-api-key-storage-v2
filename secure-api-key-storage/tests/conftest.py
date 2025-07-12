"""Pytest configuration and shared fixtures for backend tests."""

import os
import sys
import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Generator, Dict, Any
import asyncio

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "dashboard" / "backend"))

from fastapi.testclient import TestClient
from jose import jwt

# Import the FastAPI app
from dashboard.backend.main import app, SECRET_KEY, ALGORITHM, create_access_token

# Import storage classes
from src.secure_storage_rbac import SecureKeyStorageRBAC
from src.config_manager import ConfigurationManager
from src.key_rotation import KeyRotationManager
from src.rbac_models import RBACManager, Role, Permission
from src.audit_enhancement import TamperProofAuditLogger


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
def test_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp(prefix="test_secure_storage_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def test_storage(test_dir: Path) -> SecureKeyStorageRBAC:
    """Create a test storage instance."""
    storage_path = test_dir / "keys"
    rbac_db_path = test_dir / "rbac.db"
    
    # Set test master password
    os.environ["MASTER_PASSWORD"] = "test_master_password_123"
    os.environ["API_KEY_MASTER"] = "test_master_password_123"  # Fallback
    
    storage = SecureKeyStorageRBAC(
        storage_path=str(storage_path),
        master_password="test_master_password_123",
        rbac_db_path=str(rbac_db_path)
    )
    return storage


@pytest.fixture(scope="function")
def test_client() -> TestClient:
    """Create a test client for the FastAPI app."""
    # Set environment variables for testing
    os.environ["MASTER_PASSWORD"] = "test_master_password_123"
    os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_jwt"
    os.environ["CORS_ORIGINS"] = "http://localhost:3000,http://testserver"
    
    return TestClient(app)


@pytest.fixture(scope="function")
def auth_headers(test_client: TestClient) -> Dict[str, str]:
    """Get authentication headers with valid JWT token."""
    # Login to get token
    response = test_client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "test_master_password_123"}
    )
    assert response.status_code == 200
    token_data = response.json()
    
    return {"Authorization": f"Bearer {token_data['access_token']}"}


@pytest.fixture(scope="function")
def sample_keys() -> list[Dict[str, Any]]:
    """Sample API keys for testing."""
    return [
        {
            "name": "github_api_key",
            "value": "ghp_1234567890abcdef",
            "service": "GitHub",
            "description": "GitHub API access token",
            "metadata": {"environment": "production", "owner": "devops"}
        },
        {
            "name": "aws_secret_key",
            "value": "aws_secret_1234567890",
            "service": "AWS",
            "description": "AWS secret access key",
            "metadata": {"region": "us-east-1", "account_id": "123456789012"}
        },
        {
            "name": "stripe_api_key",
            "value": "sk_test_1234567890abcdef",
            "service": "Stripe",
            "description": "Stripe payment API key",
            "metadata": {"environment": "test", "webhook_secret": "whsec_test123"}
        },
    ]


@pytest.fixture(scope="function")
def config_manager(test_dir: Path) -> ConfigurationManager:
    """Create a test configuration manager."""
    config_path = test_dir / "config.json"
    return ConfigurationManager(config_path=str(config_path))


@pytest.fixture(scope="function")
def rotation_manager(config_manager: ConfigurationManager) -> KeyRotationManager:
    """Create a test key rotation manager."""
    return KeyRotationManager(config_manager)


@pytest.fixture(scope="function")
def rbac_manager(test_dir: Path) -> RBACManager:
    """Create a test RBAC manager."""
    rbac_db_path = test_dir / "rbac_test.db"
    return RBACManager(db_path=str(rbac_db_path))


@pytest.fixture(scope="function")
def audit_logger(test_dir: Path) -> TamperProofAuditLogger:
    """Create a test audit logger."""
    audit_path = test_dir / "audit.log"
    return TamperProofAuditLogger(log_file=str(audit_path))


@pytest.fixture(scope="function")
def mock_websocket():
    """Mock WebSocket for testing real-time features."""
    class MockWebSocket:
        def __init__(self):
            self.messages = []
            self.accepted = False
            
        async def accept(self):
            self.accepted = True
            
        async def send_json(self, data):
            self.messages.append(data)
            
        async def receive_text(self):
            # Simulate keeping connection alive
            await asyncio.sleep(0.1)
            return "ping"
            
    return MockWebSocket()


@pytest.fixture(scope="function")
def test_users(rbac_manager: RBACManager) -> Dict[str, Dict[str, Any]]:
    """Create test users with different roles."""
    users = {
        "admin": {
            "id": rbac_manager.create_user(
                "admin", "admin_pass123", Role.ADMIN,
                email="admin@test.com",
                metadata={"department": "IT"}
            ),
            "username": "admin",
            "password": "admin_pass123",
            "role": Role.ADMIN
        },
        "user": {
            "id": rbac_manager.create_user(
                "testuser", "user_pass123", Role.USER,
                email="user@test.com",
                metadata={"department": "Engineering"}
            ),
            "username": "testuser",
            "password": "user_pass123",
            "role": Role.USER
        },
        "viewer": {
            "id": rbac_manager.create_user(
                "viewer", "viewer_pass123", Role.VIEWER,
                email="viewer@test.com",
                metadata={"department": "Support"}
            ),
            "username": "viewer",
            "password": "viewer_pass123",
            "role": Role.VIEWER
        }
    }
    return users


@pytest.fixture
def performance_timer():
    """Timer for performance tests."""
    import time
    
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            
        def start(self):
            self.start_time = time.time()
            
        def stop(self):
            self.end_time = time.time()
            
        @property
        def elapsed(self) -> float:
            if self.start_time is None or self.end_time is None:
                return 0
            return self.end_time - self.start_time
            
    return Timer()
