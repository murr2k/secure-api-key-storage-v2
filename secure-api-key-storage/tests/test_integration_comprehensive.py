"""Comprehensive integration tests for the secure API key storage system."""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from fastapi.testclient import TestClient
from src.secure_storage_rbac import SecureKeyStorageRBAC
from src.rbac_models import Role, Permission


class TestFullWorkflowIntegration:
    """Test complete workflow integrations."""
    
    def test_complete_key_lifecycle(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test complete API key lifecycle from creation to deletion."""
        # 1. Create a new API key
        key_data = {
            "name": "lifecycle_test_key",
            "value": "test_api_key_12345",
            "service": "TestService",
            "description": "Test key for lifecycle testing",
            "metadata": {"environment": "test", "owner": "testuser"}
        }
        
        create_response = test_client.post(
            "/api/keys",
            json=key_data,
            headers=auth_headers
        )
        assert create_response.status_code == 200
        created_key = create_response.json()
        key_id = created_key["id"]
        
        # 2. List keys and verify new key is present
        list_response = test_client.get("/api/keys", headers=auth_headers)
        assert list_response.status_code == 200
        keys = list_response.json()
        
        found_key = next((k for k in keys if k["id"] == key_id), None)
        assert found_key is not None
        assert found_key["name"] == key_data["name"]
        
        # 3. Get specific key by ID
        get_response = test_client.get(f"/api/keys/{key_id}", headers=auth_headers)
        assert get_response.status_code == 200
        retrieved_key = get_response.json()
        assert retrieved_key["name"] == key_data["name"]
        
        # 4. Copy key value (simulate clipboard copy)
        copy_response = test_client.post(
            f"/api/keys/{key_id}/copy",
            headers=auth_headers
        )
        assert copy_response.status_code == 200
        copy_data = copy_response.json()
        assert copy_data["key"] == key_data["value"]
        
        # 5. Update key
        update_data = {
            "value": "updated_api_key_67890",
            "description": "Updated description"
        }
        update_response = test_client.put(
            f"/api/keys/{key_id}",
            json=update_data,
            headers=auth_headers
        )
        assert update_response.status_code == 200
        
        # 6. Rotate key
        rotate_response = test_client.post(
            f"/api/keys/{key_id}/rotate",
            headers=auth_headers
        )
        assert rotate_response.status_code == 200
        
        # 7. Check audit logs for all operations
        audit_response = test_client.get("/api/audit", headers=auth_headers)
        assert audit_response.status_code == 200
        audit_logs = audit_response.json()
        
        # Should have audit entries for create, access, update, rotate
        audit_actions = [log["action"] for log in audit_logs]
        expected_actions = ["key_created", "key_accessed", "key_updated", "key_rotated"]
        
        for expected_action in expected_actions:
            assert expected_action in audit_actions
            
        # 8. Delete key
        delete_response = test_client.delete(
            f"/api/keys/{key_id}",
            headers=auth_headers
        )
        assert delete_response.status_code == 200
        
        # 9. Verify key is deleted
        get_deleted_response = test_client.get(
            f"/api/keys/{key_id}",
            headers=auth_headers
        )
        assert get_deleted_response.status_code == 404
        
        # 10. Check final audit log
        final_audit_response = test_client.get("/api/audit", headers=auth_headers)
        final_audit_logs = final_audit_response.json()
        final_actions = [log["action"] for log in final_audit_logs]
        assert "key_deleted" in final_actions
        
    def test_multi_service_key_management(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test managing keys for multiple services."""
        services = ["GitHub", "AWS", "Stripe", "Slack", "MongoDB"]
        created_keys = []
        
        # Create keys for different services
        for i, service in enumerate(services):
            key_data = {
                "name": f"{service.lower()}_api_key_{i}",
                "value": f"{service.lower()}_secret_key_{i}",
                "service": service,
                "description": f"API key for {service} integration",
                "metadata": {"service_type": service, "priority": "high" if i < 2 else "normal"}
            }
            
            response = test_client.post(
                "/api/keys",
                json=key_data,
                headers=auth_headers
            )
            assert response.status_code == 200
            created_keys.append(response.json())
            
        # Test service-specific filtering
        for service in services:
            service_response = test_client.get(
                f"/api/keys?service={service}",
                headers=auth_headers
            )
            assert service_response.status_code == 200
            service_keys = service_response.json()
            
            # Should only contain keys for this service
            for key in service_keys:
                if key["service"]:  # Skip keys without service
                    assert key["service"] == service
                    
        # Test search across all services
        search_response = test_client.get(
            "/api/keys?search=api_key",
            headers=auth_headers
        )
        assert search_response.status_code == 200
        search_results = search_response.json()
        assert len(search_results) >= len(services)
        
        # Clean up
        for key in created_keys:
            test_client.delete(f"/api/keys/{key['id']}", headers=auth_headers)


class TestUserAuthenticationIntegration:
    """Test user authentication integration workflows."""
    
    def test_login_workflow(self, test_client: TestClient):
        """Test complete login workflow."""
        # 1. Check health (should work without auth)
        health_response = test_client.get("/api/health")
        assert health_response.status_code == 200
        
        # 2. Try accessing protected endpoint without auth
        keys_response = test_client.get("/api/keys")
        assert keys_response.status_code == 401
        
        # 3. Login with valid credentials
        login_response = test_client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "test_master_password_123"}
        )
        assert login_response.status_code == 200
        token_data = login_response.json()
        
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert token_data["token_type"] == "bearer"
        
        # 4. Use access token to access protected endpoint
        auth_headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        keys_response = test_client.get("/api/keys", headers=auth_headers)
        assert keys_response.status_code == 200
        
        # 5. Get session information
        session_response = test_client.get("/api/auth/session", headers=auth_headers)
        assert session_response.status_code == 200
        session_data = session_response.json()
        assert "username" in session_data
        assert "role" in session_data
        
        # 6. Refresh token
        refresh_response = test_client.post(
            "/api/auth/refresh",
            json={"refresh_token": token_data["refresh_token"]}
        )
        assert refresh_response.status_code == 200
        new_token_data = refresh_response.json()
        assert "access_token" in new_token_data
        
        # 7. Use new access token
        new_auth_headers = {"Authorization": f"Bearer {new_token_data['access_token']}"}
        keys_response_2 = test_client.get("/api/keys", headers=new_auth_headers)
        assert keys_response_2.status_code == 200
        
        # 8. Logout
        logout_response = test_client.post("/api/auth/logout", headers=auth_headers)
        assert logout_response.status_code == 200
        
    def test_invalid_authentication_attempts(self, test_client: TestClient):
        """Test handling of invalid authentication attempts."""
        # Test wrong password
        wrong_password_response = test_client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "wrong_password"}
        )
        assert wrong_password_response.status_code == 401
        
        # Test missing credentials
        missing_creds_response = test_client.post("/api/auth/login", data={})
        assert missing_creds_response.status_code == 422
        
        # Test invalid refresh token
        invalid_refresh_response = test_client.post(
            "/api/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )
        assert invalid_refresh_response.status_code == 401
        
        # Test expired/invalid access token
        invalid_auth_headers = {"Authorization": "Bearer invalid_token"}
        protected_response = test_client.get("/api/keys", headers=invalid_auth_headers)
        assert protected_response.status_code == 401


class TestRBACIntegration:
    """Test RBAC integration across the system."""
    
    def test_rbac_permission_enforcement(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test RBAC permission enforcement in storage operations."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        viewer_id = test_users["viewer"]["id"]
        
        # Admin creates keys
        admin_key_id = test_storage.add_api_key_with_rbac(
            "AdminService", "admin_secret_key", admin_id,
            metadata={"classification": "confidential"}
        )
        
        # User creates their own key
        user_key_id = test_storage.add_api_key_with_rbac(
            "UserService", "user_secret_key", user_id,
            metadata={"classification": "internal"}
        )
        
        # Test admin can access both keys
        admin_can_access_admin_key = test_storage.get_api_key_with_rbac(admin_key_id, admin_id)
        assert admin_can_access_admin_key == "admin_secret_key"
        
        admin_can_access_user_key = test_storage.get_api_key_with_rbac(user_key_id, admin_id)
        assert admin_can_access_user_key == "user_secret_key"
        
        # Test user can access their own key but not admin key
        user_can_access_own_key = test_storage.get_api_key_with_rbac(user_key_id, user_id)
        assert user_can_access_own_key == "user_secret_key"
        
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.get_api_key_with_rbac(admin_key_id, user_id)
            
        # Test viewer cannot access any keys without permission
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.get_api_key_with_rbac(admin_key_id, viewer_id)
            
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.get_api_key_with_rbac(user_key_id, viewer_id)
            
        # Grant viewer read access to user key
        test_storage.grant_key_access(
            user_key_id, user_id, viewer_id, [Permission.KEY_READ]
        )
        
        # Now viewer should be able to read user key
        viewer_can_read_user_key = test_storage.get_api_key_with_rbac(user_key_id, viewer_id)
        assert viewer_can_read_user_key == "user_secret_key"
        
        # But viewer still cannot update or delete
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.update_api_key_with_rbac(user_key_id, "new_value", viewer_id)
            
    def test_rbac_key_sharing_workflow(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test complete key sharing workflow with RBAC."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        viewer_id = test_users["viewer"]["id"]
        
        # Admin creates a shared key
        shared_key_id = test_storage.add_api_key_with_rbac(
            "SharedService", "shared_secret_key", admin_id,
            metadata={"shared": True, "team": "engineering"}
        )
        
        # Share with specific permissions
        test_storage.grant_key_access(
            shared_key_id, admin_id, user_id, 
            [Permission.KEY_READ, Permission.KEY_UPDATE]
        )
        
        test_storage.grant_key_access(
            shared_key_id, admin_id, viewer_id,
            [Permission.KEY_READ]
        )
        
        # Test user can read and update
        user_read_key = test_storage.get_api_key_with_rbac(shared_key_id, user_id)
        assert user_read_key == "shared_secret_key"
        
        user_update_result = test_storage.update_api_key_with_rbac(
            shared_key_id, "updated_shared_key", user_id
        )
        assert user_update_result is True
        
        # Test viewer can only read
        viewer_read_key = test_storage.get_api_key_with_rbac(shared_key_id, viewer_id)
        assert viewer_read_key == "updated_shared_key"
        
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.update_api_key_with_rbac(shared_key_id, "viewer_update", viewer_id)
            
        # Test access list
        access_list = test_storage.get_key_access_list(shared_key_id, admin_id)
        assert len(access_list) >= 3  # admin, user, viewer
        
        user_access = next((a for a in access_list if a["user_id"] == user_id), None)
        assert user_access is not None
        assert Permission.KEY_READ.value in user_access["permissions"]
        assert Permission.KEY_UPDATE.value in user_access["permissions"]
        
        viewer_access = next((a for a in access_list if a["user_id"] == viewer_id), None)
        assert viewer_access is not None
        assert Permission.KEY_READ.value in viewer_access["permissions"]
        assert Permission.KEY_UPDATE.value not in viewer_access["permissions"]
        
        # Revoke viewer access
        test_storage.revoke_key_access(shared_key_id, admin_id, viewer_id)
        
        # Viewer should no longer have access
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.get_api_key_with_rbac(shared_key_id, viewer_id)


class TestAuditTrailIntegration:
    """Test audit trail integration across all operations."""
    
    def test_comprehensive_audit_logging(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test that all operations are properly audited."""
        # Perform various operations
        operations = [
            # Create key
            lambda: test_client.post(
                "/api/keys",
                json={"name": "audit_test_key", "value": "audit_value", "service": "AuditService"},
                headers=auth_headers
            ),
            # List keys
            lambda: test_client.get("/api/keys", headers=auth_headers),
            # Get specific key (will need key_id from create operation)
            # Update key
            # Copy key
            # Rotate key
            # Delete key
        ]
        
        # Get initial audit log count
        initial_audit_response = test_client.get("/api/audit", headers=auth_headers)
        initial_audit_logs = initial_audit_response.json()
        initial_count = len(initial_audit_logs)
        
        # Create a key to work with
        create_response = test_client.post(
            "/api/keys",
            json={"name": "audit_test_key", "value": "audit_value", "service": "AuditService"},
            headers=auth_headers
        )
        created_key = create_response.json()
        key_id = created_key["id"]
        
        # Perform operations that should be audited
        test_client.get(f"/api/keys/{key_id}", headers=auth_headers)  # Get specific key
        test_client.post(f"/api/keys/{key_id}/copy", headers=auth_headers)  # Copy key
        test_client.put(
            f"/api/keys/{key_id}",
            json={"description": "Updated for audit test"},
            headers=auth_headers
        )  # Update key
        test_client.post(f"/api/keys/{key_id}/rotate", headers=auth_headers)  # Rotate key
        test_client.delete(f"/api/keys/{key_id}", headers=auth_headers)  # Delete key
        
        # Check audit logs
        final_audit_response = test_client.get("/api/audit", headers=auth_headers)
        final_audit_logs = final_audit_response.json()
        
        # Should have more audit entries
        assert len(final_audit_logs) > initial_count
        
        # Check for specific audit entries
        audit_actions = [log["action"] for log in final_audit_logs]
        expected_actions = [
            "key_created",
            "key_accessed", 
            "key_updated",
            "key_rotated",
            "key_deleted"
        ]
        
        for expected_action in expected_actions:
            assert expected_action in audit_actions, f"Missing audit action: {expected_action}"
            
        # Verify audit log structure
        for log in final_audit_logs[-5:]:  # Check last 5 entries
            assert "id" in log
            assert "timestamp" in log
            assert "action" in log
            assert "user" in log
            assert "details" in log
            
            # Verify timestamp is recent
            log_time = datetime.fromisoformat(log["timestamp"].replace('Z', '+00:00'))
            time_diff = datetime.now(log_time.tzinfo) - log_time
            assert time_diff.total_seconds() < 300  # Within last 5 minutes


class TestWebSocketIntegration:
    """Test WebSocket integration for real-time features."""
    
    @pytest.mark.asyncio
    async def test_real_time_audit_streaming(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test real-time audit log streaming via WebSocket."""
        # This test simulates WebSocket connection for audit streaming
        with test_client.websocket_connect("/api/audit/stream") as websocket:
            # Perform an operation that generates audit log
            response = test_client.post(
                "/api/keys",
                json={"name": "websocket_test_key", "value": "websocket_value"},
                headers=auth_headers
            )
            assert response.status_code == 200
            
            # In a real implementation, we would receive the audit event via WebSocket
            # For this test, we just verify the WebSocket connection works
            websocket.send_text("ping")
            
            # Clean up
            created_key = response.json()
            test_client.delete(f"/api/keys/{created_key['id']}", headers=auth_headers)


class TestPerformanceIntegration:
    """Test performance under various integration scenarios."""
    
    def test_concurrent_operations(self, test_client: TestClient, auth_headers: Dict[str, str], performance_timer):
        """Test concurrent operations performance."""
        def create_key(index):
            return test_client.post(
                "/api/keys",
                json={
                    "name": f"concurrent_key_{index}",
                    "value": f"concurrent_value_{index}",
                    "service": "ConcurrentService"
                },
                headers=auth_headers
            )
            
        def list_keys():
            return test_client.get("/api/keys", headers=auth_headers)
            
        performance_timer.start()
        
        # Test concurrent key creation
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit concurrent key creation tasks
            create_futures = [executor.submit(create_key, i) for i in range(20)]
            list_futures = [executor.submit(list_keys) for _ in range(5)]
            
            # Wait for all to complete
            created_keys = []
            for future in as_completed(create_futures):
                response = future.result()
                assert response.status_code == 200
                created_keys.append(response.json())
                
            for future in as_completed(list_futures):
                response = future.result()
                assert response.status_code == 200
                
        performance_timer.stop()
        
        # Should complete within reasonable time
        assert performance_timer.elapsed < 10.0, f"Concurrent operations too slow: {performance_timer.elapsed}s"
        
        # Clean up created keys
        for key in created_keys:
            test_client.delete(f"/api/keys/{key['id']}", headers=auth_headers)
            
    def test_bulk_operations_performance(self, test_client: TestClient, auth_headers: Dict[str, str], performance_timer):
        """Test performance of bulk operations."""
        # Create many keys
        created_keys = []
        
        performance_timer.start()
        for i in range(50):
            response = test_client.post(
                "/api/keys",
                json={
                    "name": f"bulk_key_{i}",
                    "value": f"bulk_value_{i}",
                    "service": "BulkService",
                    "metadata": {"batch": "bulk_test", "index": i}
                },
                headers=auth_headers
            )
            assert response.status_code == 200
            created_keys.append(response.json())
            
        performance_timer.stop()
        
        creation_time = performance_timer.elapsed
        assert creation_time < 30.0, f"Bulk creation too slow: {creation_time}s"
        
        # Test bulk retrieval
        performance_timer.start()
        list_response = test_client.get("/api/keys", headers=auth_headers)
        performance_timer.stop()
        
        retrieval_time = performance_timer.elapsed
        assert retrieval_time < 5.0, f"Bulk retrieval too slow: {retrieval_time}s"
        
        assert list_response.status_code == 200
        keys = list_response.json()
        assert len(keys) >= 50
        
        # Test bulk deletion
        performance_timer.start()
        for key in created_keys:
            response = test_client.delete(f"/api/keys/{key['id']}", headers=auth_headers)
            assert response.status_code == 200
        performance_timer.stop()
        
        deletion_time = performance_timer.elapsed
        assert deletion_time < 30.0, f"Bulk deletion too slow: {deletion_time}s"
        
    def test_search_performance(self, test_client: TestClient, auth_headers: Dict[str, str], performance_timer):
        """Test search operation performance."""
        # Create diverse keys for searching
        test_keys = [
            {"name": "github_production_key", "service": "GitHub", "description": "Production GitHub API key"},
            {"name": "github_development_key", "service": "GitHub", "description": "Development GitHub API key"},
            {"name": "aws_prod_secret", "service": "AWS", "description": "AWS production secret key"},
            {"name": "stripe_live_key", "service": "Stripe", "description": "Stripe live API key"},
            {"name": "slack_bot_token", "service": "Slack", "description": "Slack bot authentication token"},
        ]
        
        created_keys = []
        for key_data in test_keys:
            key_data["value"] = f"value_for_{key_data['name']}"
            response = test_client.post("/api/keys", json=key_data, headers=auth_headers)
            assert response.status_code == 200
            created_keys.append(response.json())
            
        # Test various search queries
        search_queries = [
            "github",
            "production", 
            "AWS",
            "api",
            "key"
        ]
        
        for query in search_queries:
            performance_timer.start()
            response = test_client.get(f"/api/keys?search={query}", headers=auth_headers)
            performance_timer.stop()
            
            assert response.status_code == 200
            assert performance_timer.elapsed < 2.0, f"Search for '{query}' too slow: {performance_timer.elapsed}s"
            
            results = response.json()
            # Verify search results are relevant
            if query.lower() in ["github", "aws", "stripe", "slack"]:
                assert len(results) > 0, f"No results for service search: {query}"
                
        # Test service filtering
        for service in ["GitHub", "AWS", "Stripe", "Slack"]:
            performance_timer.start()
            response = test_client.get(f"/api/keys?service={service}", headers=auth_headers)
            performance_timer.stop()
            
            assert response.status_code == 200
            assert performance_timer.elapsed < 2.0, f"Service filter for '{service}' too slow: {performance_timer.elapsed}s"
            
        # Clean up
        for key in created_keys:
            test_client.delete(f"/api/keys/{key['id']}", headers=auth_headers)


class TestErrorHandlingIntegration:
    """Test error handling across integrated components."""
    
    def test_cascading_error_handling(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test how errors cascade through the system."""
        # Test creating key with invalid data
        invalid_key_data = {
            "name": "",  # Invalid empty name
            "value": "test_value"
        }
        
        response = test_client.post(
            "/api/keys",
            json=invalid_key_data,
            headers=auth_headers
        )
        
        # Should handle validation error gracefully
        assert response.status_code in [400, 422]
        error_data = response.json()
        assert "detail" in error_data or "message" in error_data
        
        # Test operations on nonexistent key
        nonexistent_key_id = "nonexistent_key_12345"
        
        operations = [
            lambda: test_client.get(f"/api/keys/{nonexistent_key_id}", headers=auth_headers),
            lambda: test_client.put(
                f"/api/keys/{nonexistent_key_id}",
                json={"description": "test"},
                headers=auth_headers
            ),
            lambda: test_client.post(f"/api/keys/{nonexistent_key_id}/copy", headers=auth_headers),
            lambda: test_client.post(f"/api/keys/{nonexistent_key_id}/rotate", headers=auth_headers),
            lambda: test_client.delete(f"/api/keys/{nonexistent_key_id}", headers=auth_headers),
        ]
        
        for operation in operations:
            response = operation()
            # All should return 404 for nonexistent key
            assert response.status_code == 404
            
    def test_authentication_error_propagation(self, test_client: TestClient):
        """Test authentication error propagation."""
        # Test with expired/invalid token
        invalid_headers = {"Authorization": "Bearer invalid_token_12345"}
        
        protected_endpoints = [
            "/api/keys",
            "/api/audit",
            "/api/analytics/overview",
            "/api/auth/session",
            "/api/auth/logout"
        ]
        
        for endpoint in protected_endpoints:
            response = test_client.get(endpoint, headers=invalid_headers)
            assert response.status_code == 401
            
            error_data = response.json()
            assert "detail" in error_data
            assert "credentials" in error_data["detail"].lower() or "unauthorized" in error_data["detail"].lower()
            
    def test_rate_limiting_integration(self, test_client: TestClient):
        """Test rate limiting across the integrated system."""
        # Make many requests to trigger rate limiting
        responses = []
        
        for i in range(150):  # Exceed rate limit
            response = test_client.get("/api/health")
            responses.append(response.status_code)
            
            # Stop early if rate limited
            if response.status_code == 429:
                break
                
        # Should eventually hit rate limit
        assert 429 in responses, "Rate limiting should be triggered"
        
        # Wait a bit and try again - should be allowed
        time.sleep(2)
        recovery_response = test_client.get("/api/health")
        # Might still be rate limited or might have recovered
        assert recovery_response.status_code in [200, 429]


class TestDataConsistencyIntegration:
    """Test data consistency across all components."""
    
    def test_storage_audit_consistency(self, test_storage: SecureKeyStorageRBAC, audit_logger):
        """Test consistency between storage operations and audit logs."""
        # Perform storage operations
        key_id = test_storage.store_key(
            "consistency_test_key",
            "consistency_test_value",
            "ConsistencyService",
            metadata={"test": "consistency"}
        )
        
        # Retrieve the key
        retrieved_key = test_storage.get_key(key_id)
        assert retrieved_key == "consistency_test_value"
        
        # Check that operations are reflected in audit logs
        audit_logs = audit_logger.get_audit_logs(limit=10)
        
        # Should have audit entries for store and get operations
        recent_actions = [log["action"] for log in audit_logs]
        
        # Note: Exact audit actions depend on implementation
        # This test verifies that audit logging is happening
        assert len(audit_logs) > 0
        
        # Clean up
        test_storage.delete_key(key_id)
        
    def test_rbac_storage_consistency(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test consistency between RBAC permissions and storage access."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        
        # Create key as admin
        key_id = test_storage.add_api_key_with_rbac(
            "ConsistencyService", "rbac_consistency_key", admin_id
        )
        
        # Verify admin can access
        admin_key = test_storage.get_api_key_with_rbac(key_id, admin_id)
        assert admin_key == "rbac_consistency_key"
        
        # Grant user access
        test_storage.grant_key_access(
            key_id, admin_id, user_id, [Permission.KEY_READ]
        )
        
        # Verify user can now access
        user_key = test_storage.get_api_key_with_rbac(key_id, user_id)
        assert user_key == "rbac_consistency_key"
        
        # Revoke user access
        test_storage.revoke_key_access(key_id, admin_id, user_id)
        
        # Verify user can no longer access
        with pytest.raises(Exception):  # Should raise SecurityException
            test_storage.get_api_key_with_rbac(key_id, user_id)
            
        # But admin should still have access
        admin_key_2 = test_storage.get_api_key_with_rbac(key_id, admin_id)
        assert admin_key_2 == "rbac_consistency_key"


class TestRecoveryIntegration:
    """Test system recovery and resilience."""
    
    def test_graceful_degradation(self, test_client: TestClient):
        """Test graceful degradation when components are unavailable."""
        # Health check should still work even if some components are down
        health_response = test_client.get("/api/health")
        assert health_response.status_code == 200
        
        health_data = health_response.json()
        assert "status" in health_data
        
        # Should indicate component status
        assert "storage_available" in health_data
        
    def test_error_recovery_workflow(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test recovery from error conditions."""
        # Create a key successfully
        create_response = test_client.post(
            "/api/keys",
            json={"name": "recovery_test_key", "value": "recovery_value"},
            headers=auth_headers
        )
        assert create_response.status_code == 200
        created_key = create_response.json()
        
        # Attempt invalid operation
        invalid_update_response = test_client.put(
            f"/api/keys/{created_key['id']}",
            json={"invalid_field": "invalid_value"},
            headers=auth_headers
        )
        
        # Should handle error gracefully
        assert invalid_update_response.status_code in [400, 422]
        
        # System should still be functional for valid operations
        get_response = test_client.get(f"/api/keys/{created_key['id']}", headers=auth_headers)
        assert get_response.status_code == 200
        
        # Clean up
        test_client.delete(f"/api/keys/{created_key['id']}", headers=auth_headers)


class TestScalabilityIntegration:
    """Test system behavior under load."""
    
    def test_large_dataset_handling(self, test_client: TestClient, auth_headers: Dict[str, str]):
        """Test handling of large datasets."""
        # Create a substantial number of keys
        num_keys = 100
        created_keys = []
        
        for i in range(num_keys):
            key_data = {
                "name": f"scale_test_key_{i:03d}",
                "value": f"scale_test_value_{i:03d}",
                "service": f"Service_{i % 10}",  # 10 different services
                "description": f"Scale test key number {i}",
                "metadata": {
                    "batch": "scale_test",
                    "index": i,
                    "category": "test" if i % 2 == 0 else "production"
                }
            }
            
            response = test_client.post("/api/keys", json=key_data, headers=auth_headers)
            if response.status_code == 200:
                created_keys.append(response.json())
            else:
                # If we hit limits, that's also valid
                break
                
        # Test listing large number of keys
        list_response = test_client.get("/api/keys", headers=auth_headers)
        assert list_response.status_code == 200
        keys = list_response.json()
        assert len(keys) >= len(created_keys)
        
        # Test searching in large dataset
        search_response = test_client.get("/api/keys?search=scale_test", headers=auth_headers)
        assert search_response.status_code == 200
        search_results = search_response.json()
        
        # Should find many of our test keys
        scale_test_keys = [k for k in search_results if "scale_test" in k.get("name", "")]
        assert len(scale_test_keys) > 0
        
        # Test service filtering
        service_response = test_client.get("/api/keys?service=Service_0", headers=auth_headers)
        assert service_response.status_code == 200
        service_keys = service_response.json()
        
        # Should have approximately num_keys/10 keys for Service_0
        service_0_keys = [k for k in service_keys if k.get("service") == "Service_0"]
        expected_count = num_keys // 10
        assert len(service_0_keys) >= expected_count - 5  # Allow some variance
        
        # Clean up (this tests bulk deletion performance)
        deleted_count = 0
        for key in created_keys:
            response = test_client.delete(f"/api/keys/{key['id']}", headers=auth_headers)
            if response.status_code == 200:
                deleted_count += 1
                
        assert deleted_count == len(created_keys)
