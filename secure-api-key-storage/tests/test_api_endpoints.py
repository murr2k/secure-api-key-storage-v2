"""Comprehensive API endpoint tests for the secure API key storage system."""

import pytest
import json
from datetime import datetime, timedelta
from typing import Dict, Any
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_check(self, test_client: TestClient):
        """Test basic health check endpoint."""
        response = test_client.get("/api/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "master_password_set" in data
        assert "jwt_secret_set" in data
        assert "storage_available" in data
        
    def test_health_check_performance(self, test_client: TestClient, performance_timer):
        """Test health check response time."""
        performance_timer.start()
        response = test_client.get("/api/health")
        performance_timer.stop()
        
        assert response.status_code == 200
        assert performance_timer.elapsed < 1.0  # Should respond within 1 second


class TestAuthenticationEndpoints:
    """Test authentication endpoints."""
    
    def test_login_with_valid_credentials(self, test_client: TestClient):
        """Test login with valid master password."""
        response = test_client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "test_master_password_123"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        
    def test_login_with_invalid_credentials(self, test_client: TestClient):
        """Test login with invalid master password."""
        response = test_client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "wrong_password"}
        )
        
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert "Incorrect master password" in data["detail"]
        
    def test_login_missing_credentials(self, test_client: TestClient):
        """Test login with missing credentials."""
        response = test_client.post("/api/auth/login", data={})
        
        assert response.status_code == 422  # Validation error
        
    def test_refresh_token_valid(self, test_client: TestClient):
        """Test refresh token with valid token."""
        # First login to get tokens
        login_response = test_client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "test_master_password_123"}
        )
        login_data = login_response.json()
        
        # Use refresh token
        response = test_client.post(
            "/api/auth/refresh",
            json={"refresh_token": login_data["refresh_token"]}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        
    def test_refresh_token_invalid(self, test_client: TestClient):
        """Test refresh token with invalid token."""
        response = test_client.post(
            "/api/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )
        
        assert response.status_code == 401
        
    def test_logout(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test logout endpoint."""
        response = test_client.post("/api/auth/logout", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        
    def test_get_session(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test get session endpoint."""
        response = test_client.get("/api/auth/session", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "username" in data
        assert "role" in data
        
    def test_unauthorized_access(self, test_client: TestClient):
        """Test access without authentication."""
        response = test_client.get("/api/auth/session")
        
        assert response.status_code == 401


class TestKeyManagementEndpoints:
    """Test API key management endpoints."""
    
    def test_list_keys_empty(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test listing keys when none exist."""
        response = test_client.get("/api/keys", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
    def test_create_key(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test creating a new API key."""
        key_data = {
            "name": "test_api_key",
            "value": "test_value_12345",
            "service": "TestService",
            "description": "A test API key",
            "metadata": {"env": "test"}
        }
        
        response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "id" in data
        assert data["name"] == key_data["name"]
        assert data["service"] == key_data["service"]
        assert data["description"] == key_data["description"]
        assert "created_at" in data
        assert "updated_at" in data
        
    def test_create_key_minimal_data(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test creating a key with minimal required data."""
        key_data = {
            "name": "minimal_key",
            "value": "minimal_value"
        }
        
        response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == key_data["name"]
        
    def test_create_key_invalid_data(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test creating a key with invalid data."""
        key_data = {
            "name": "",  # Empty name
            "value": "test_value"
        }
        
        response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        
        # This might be 422 or 400 depending on validation
        assert response.status_code in [400, 422]
        
    def test_list_keys_after_creation(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test listing keys after creating some."""
        # Create a key first
        key_data = {
            "name": "list_test_key",
            "value": "list_test_value",
            "service": "TestService"
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        assert create_response.status_code == 200
        
        # List keys
        response = test_client.get("/api/keys", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        
        # Find our created key
        created_key = next((k for k in data if k["name"] == key_data["name"]), None)
        assert created_key is not None
        
    def test_list_keys_with_service_filter(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test listing keys with service filter."""
        # Create keys with different services
        key1_data = {
            "name": "service1_key",
            "value": "value1",
            "service": "Service1"
        }
        key2_data = {
            "name": "service2_key",
            "value": "value2",
            "service": "Service2"
        }
        
        # Create both keys
        test_client.post("/api/keys", json=key1_data, headers=auth_headers)
        test_client.post("/api/keys", json=key2_data, headers=auth_headers)
        
        # Filter by service
        response = test_client.get("/api/keys?service=Service1", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should only contain Service1 keys
        for key in data:
            if key["service"]:  # Skip keys without service
                assert key["service"] == "Service1"
                
    def test_list_keys_with_search(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test listing keys with search filter."""
        # Create a key with searchable content
        key_data = {
            "name": "searchable_github_key",
            "value": "value123",
            "service": "GitHub",
            "description": "GitHub API access token"
        }
        
        test_client.post("/api/keys", json=key_data, headers=auth_headers)
        
        # Search by name
        response = test_client.get("/api/keys?search=github", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should find our key
        found = any("github" in k["name"].lower() for k in data)
        assert found
        
    def test_get_key_by_id(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test getting a specific key by ID."""
        # Create a key first
        key_data = {
            "name": "get_test_key",
            "value": "get_test_value",
            "service": "TestService"
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        created_key = create_response.json()
        
        # Get the key by ID
        response = test_client.get(
            f"/api/keys/{created_key['id']}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == key_data["name"]
        
    def test_get_nonexistent_key(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test getting a key that doesn't exist."""
        response = test_client.get(
            "/api/keys/nonexistent_key_id",
            headers=auth_headers
        )
        
        assert response.status_code == 404
        
    def test_update_key(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test updating an existing key."""
        # Create a key first
        key_data = {
            "name": "update_test_key",
            "value": "original_value",
            "service": "TestService"
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        created_key = create_response.json()
        
        # Update the key
        update_data = {
            "value": "updated_value",
            "description": "Updated description"
        }
        
        response = test_client.put(
            f"/api/keys/{created_key['id']}",
            json=update_data,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        
    def test_delete_key(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test deleting a key."""
        # Create a key first
        key_data = {
            "name": "delete_test_key",
            "value": "delete_test_value",
            "service": "TestService"
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        created_key = create_response.json()
        
        # Delete the key
        response = test_client.delete(
            f"/api/keys/{created_key['id']}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        
        # Verify key is deleted
        get_response = test_client.get(
            f"/api/keys/{created_key['id']}",
            headers=auth_headers
        )
        assert get_response.status_code == 404
        
    def test_copy_key(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test copying key value to clipboard."""
        # Create a key first
        key_data = {
            "name": "copy_test_key",
            "value": "copy_test_value",
            "service": "TestService"
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        created_key = create_response.json()
        
        # Copy the key
        response = test_client.post(
            f"/api/keys/{created_key['id']}/copy",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "key" in data
        assert data["key"] == key_data["value"]
        
    def test_rotate_key(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test key rotation."""
        # Create a key first
        key_data = {
            "name": "rotate_test_key",
            "value": "rotate_test_value",
            "service": "TestService"
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        created_key = create_response.json()
        
        # Rotate the key
        response = test_client.post(
            f"/api/keys/{created_key['id']}/rotate",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "new_key_preview" in data


class TestAuditEndpoints:
    """Test audit log endpoints."""
    
    def test_get_audit_logs(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test getting audit logs."""
        response = test_client.get("/api/audit", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # Check audit log structure if logs exist
        if data:
            log_entry = data[0]
            assert "id" in log_entry
            assert "timestamp" in log_entry
            assert "action" in log_entry
            assert "user" in log_entry
            assert "details" in log_entry
            
    def test_get_audit_logs_with_pagination(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test audit logs with pagination."""
        response = test_client.get("/api/audit?skip=0&limit=10", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 10
        
    def test_get_audit_logs_with_filters(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test audit logs with filters."""
        response = test_client.get(
            "/api/audit?action=key_accessed&key_name=test_key",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestAnalyticsEndpoints:
    """Test analytics endpoints."""
    
    def test_get_analytics_overview(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test getting analytics overview."""
        response = test_client.get("/api/analytics/overview", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "total_keys" in data
        assert "total_services" in data
        assert "keys_accessed_today" in data
        assert "keys_rotated_this_month" in data
        assert "upcoming_rotations" in data
        assert "recent_activity" in data
        
        assert isinstance(data["total_keys"], int)
        assert isinstance(data["total_services"], int)
        assert isinstance(data["recent_activity"], list)


class TestWebSocketEndpoints:
    """Test WebSocket endpoints."""
    
    @pytest.mark.asyncio
    async def test_audit_stream_websocket(self, test_client: TestClient):
        """Test WebSocket audit log streaming."""
        with test_client.websocket_connect("/api/audit/stream") as websocket:
            # WebSocket should connect successfully
            assert websocket is not None
            
            # Send a ping to keep connection alive
            websocket.send_text("ping")
            
            # The connection should remain open
            # In a real test, we would trigger an audit event and verify it's received


class TestErrorHandling:
    """Test error handling across endpoints."""
    
    def test_unauthorized_requests(self, test_client: TestClient):
        """Test that protected endpoints require authentication."""
        protected_endpoints = [
            ("/api/keys", "GET"),
            ("/api/keys", "POST"),
            ("/api/keys/test", "GET"),
            ("/api/keys/test", "PUT"),
            ("/api/keys/test", "DELETE"),
            ("/api/audit", "GET"),
            ("/api/analytics/overview", "GET"),
        ]
        
        for endpoint, method in protected_endpoints:
            if method == "GET":
                response = test_client.get(endpoint)
            elif method == "POST":
                response = test_client.post(endpoint, json={})
            elif method == "PUT":
                response = test_client.put(endpoint, json={})
            elif method == "DELETE":
                response = test_client.delete(endpoint)
                
            assert response.status_code == 401, f"Endpoint {method} {endpoint} should require auth"
            
    def test_invalid_content_type(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test endpoints with invalid content types."""
        response = test_client.post(
            "/api/keys",
            data="invalid data",  # Not JSON
            headers={**auth_headers, "Content-Type": "text/plain"}
        )
        
        assert response.status_code in [400, 422]  # Bad request or validation error
        
    def test_large_payload(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test handling of large payloads."""
        # Create a large metadata object
        large_metadata = {f"key_{i}": f"value_{i}" * 100 for i in range(1000)}
        
        key_data = {
            "name": "large_payload_key",
            "value": "test_value",
            "metadata": large_metadata
        }
        
        response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        
        # Should either accept it or reject with appropriate error
        assert response.status_code in [200, 413, 422]  # Success, payload too large, or validation error
        
    def test_sql_injection_protection(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test protection against SQL injection attempts."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "<script>alert('xss')</script>"
        ]
        
        for malicious_input in malicious_inputs:
            # Test in key name
            key_data = {
                "name": malicious_input,
                "value": "test_value"
            }
            
            response = test_client.post(
                "/api/keys",
                json=key_data,
                headers=auth_headers
            )
            
            # Should not cause server errors
            assert response.status_code != 500
            
            # Test in search parameter
            response = test_client.get(
                f"/api/keys?search={malicious_input}",
                headers=auth_headers
            )
            
            assert response.status_code != 500


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_rate_limiting(self, test_client: TestClient):
        """Test that rate limiting is enforced."""
        # Make many requests quickly
        responses = []
        for i in range(150):  # Exceed the 100 calls per minute limit
            response = test_client.get("/api/health")
            responses.append(response.status_code)
            
            # Stop if we hit rate limit
            if response.status_code == 429:
                break
                
        # Should eventually hit rate limit
        assert 429 in responses, "Rate limiting should be enforced"


class TestCORSHandling:
    """Test CORS handling."""
    
    def test_cors_headers(self, test_client: TestClient):
        """Test that CORS headers are set correctly."""
        response = test_client.options(
            "/api/health",
            headers={"Origin": "http://localhost:3000"}
        )
        
        # CORS headers should be present
        assert "access-control-allow-origin" in response.headers
        
    def test_cors_preflight(self, test_client: TestClient):
        """Test CORS preflight requests."""
        response = test_client.options(
            "/api/keys",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization, content-type"
            }
        )
        
        assert response.status_code in [200, 204]
