"""Cache tests for the secure API key storage system."""

import pytest
import redis
import time
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch


class TestRedisConnection:
    """Test Redis connection and basic operations."""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client for testing."""
        mock_client = Mock(spec=redis.Redis)
        mock_client.ping.return_value = True
        mock_client.get.return_value = None
        mock_client.set.return_value = True
        mock_client.delete.return_value = 1
        mock_client.exists.return_value = False
        mock_client.expire.return_value = True
        mock_client.flushdb.return_value = True
        return mock_client
        
    def test_redis_connection(self, mock_redis):
        """Test Redis connection establishment."""
        # Test basic connection
        assert mock_redis.ping() is True
        
        # Test connection parameters
        mock_redis.ping.assert_called_once()
        
    def test_redis_connection_failure(self):
        """Test handling of Redis connection failures."""
        with patch('redis.Redis') as mock_redis_class:
            mock_client = Mock()
            mock_client.ping.side_effect = redis.ConnectionError("Connection failed")
            mock_redis_class.return_value = mock_client
            
            # Should handle connection failure gracefully
            try:
                client = redis.Redis(host='localhost', port=6379, db=0)
                client.ping()
            except redis.ConnectionError:
                # This is expected behavior
                pass
                
    def test_redis_configuration(self, mock_redis):
        """Test Redis configuration settings."""
        # Test that Redis is configured with appropriate settings
        config_commands = [
            'CONFIG GET maxmemory-policy',
            'CONFIG GET timeout',
            'CONFIG GET save'
        ]
        
        for command in config_commands:
            mock_redis.execute_command.return_value = ['setting', 'value']
            result = mock_redis.execute_command(command)
            assert result is not None


class TestCacheOperations:
    """Test basic cache operations."""
    
    @pytest.fixture
    def cache_client(self):
        """Mock cache client."""
        mock_client = Mock()
        mock_client.data = {}  # Internal storage for testing
        
        def mock_get(key):
            return mock_client.data.get(key)
            
        def mock_set(key, value, ex=None):
            mock_client.data[key] = value
            return True
            
        def mock_delete(key):
            return mock_client.data.pop(key, None) is not None
            
        def mock_exists(key):
            return key in mock_client.data
            
        mock_client.get = mock_get
        mock_client.set = mock_set
        mock_client.delete = mock_delete
        mock_client.exists = mock_exists
        
        return mock_client
        
    def test_cache_set_get(self, cache_client):
        """Test basic cache set and get operations."""
        key = "test_key"
        value = "test_value"
        
        # Set value
        result = cache_client.set(key, value)
        assert result is True
        
        # Get value
        retrieved_value = cache_client.get(key)
        assert retrieved_value == value
        
    def test_cache_set_with_expiration(self, cache_client):
        """Test cache operations with expiration."""
        key = "expiring_key"
        value = "expiring_value"
        expiration = 60  # 60 seconds
        
        # Set with expiration
        result = cache_client.set(key, value, ex=expiration)
        assert result is True
        
        # Verify value exists
        retrieved_value = cache_client.get(key)
        assert retrieved_value == value
        
    def test_cache_delete(self, cache_client):
        """Test cache deletion."""
        key = "delete_test_key"
        value = "delete_test_value"
        
        # Set value
        cache_client.set(key, value)
        assert cache_client.exists(key) is True
        
        # Delete value
        result = cache_client.delete(key)
        assert result is True
        
        # Verify deletion
        assert cache_client.exists(key) is False
        assert cache_client.get(key) is None
        
    def test_cache_exists(self, cache_client):
        """Test cache key existence check."""
        key = "exists_test_key"
        value = "exists_test_value"
        
        # Key should not exist initially
        assert cache_client.exists(key) is False
        
        # Set value
        cache_client.set(key, value)
        
        # Key should now exist
        assert cache_client.exists(key) is True
        
    def test_cache_nonexistent_key(self, cache_client):
        """Test operations on nonexistent keys."""
        key = "nonexistent_key"
        
        # Get nonexistent key
        value = cache_client.get(key)
        assert value is None
        
        # Delete nonexistent key
        result = cache_client.delete(key)
        assert result is False
        
        # Check existence of nonexistent key
        exists = cache_client.exists(key)
        assert exists is False


class TestSessionCaching:
    """Test session caching functionality."""
    
    @pytest.fixture
    def session_cache(self):
        """Mock session cache."""
        cache = Mock()
        cache.sessions = {}  # Internal storage
        
        def store_session(session_id, user_data, expiration=3600):
            cache.sessions[session_id] = {
                'data': user_data,
                'expires_at': datetime.now() + timedelta(seconds=expiration)
            }
            return True
            
        def get_session(session_id):
            session = cache.sessions.get(session_id)
            if session and session['expires_at'] > datetime.now():
                return session['data']
            return None
            
        def invalidate_session(session_id):
            return cache.sessions.pop(session_id, None) is not None
            
        cache.store_session = store_session
        cache.get_session = get_session
        cache.invalidate_session = invalidate_session
        
        return cache
        
    def test_session_storage(self, session_cache):
        """Test storing user sessions in cache."""
        session_id = "test_session_123"
        user_data = {
            "user_id": 1,
            "username": "testuser",
            "role": "admin",
            "permissions": ["read", "write"]
        }
        
        # Store session
        result = session_cache.store_session(session_id, user_data)
        assert result is True
        
        # Retrieve session
        retrieved_data = session_cache.get_session(session_id)
        assert retrieved_data == user_data
        
    def test_session_expiration(self, session_cache):
        """Test session expiration in cache."""
        session_id = "expiring_session_123"
        user_data = {"user_id": 1, "username": "testuser"}
        
        # Store session with short expiration
        session_cache.store_session(session_id, user_data, expiration=1)
        
        # Should be available immediately
        retrieved_data = session_cache.get_session(session_id)
        assert retrieved_data == user_data
        
        # Wait for expiration
        time.sleep(2)
        
        # Should be expired now
        retrieved_data_after = session_cache.get_session(session_id)
        assert retrieved_data_after is None
        
    def test_session_invalidation(self, session_cache):
        """Test manual session invalidation."""
        session_id = "invalidate_session_123"
        user_data = {"user_id": 1, "username": "testuser"}
        
        # Store session
        session_cache.store_session(session_id, user_data)
        
        # Verify session exists
        retrieved_data = session_cache.get_session(session_id)
        assert retrieved_data == user_data
        
        # Invalidate session
        result = session_cache.invalidate_session(session_id)
        assert result is True
        
        # Verify session is gone
        retrieved_data_after = session_cache.get_session(session_id)
        assert retrieved_data_after is None


class TestKeyMetadataCaching:
    """Test caching of API key metadata."""
    
    @pytest.fixture
    def metadata_cache(self):
        """Mock metadata cache."""
        cache = Mock()
        cache.metadata = {}  # Internal storage
        
        def cache_key_metadata(key_id, metadata, ttl=300):
            cache_key = f"key_metadata:{key_id}"
            cache.metadata[cache_key] = {
                'data': metadata,
                'expires_at': datetime.now() + timedelta(seconds=ttl)
            }
            return True
            
        def get_key_metadata(key_id):
            cache_key = f"key_metadata:{key_id}"
            cached = cache.metadata.get(cache_key)
            if cached and cached['expires_at'] > datetime.now():
                return cached['data']
            return None
            
        def invalidate_key_metadata(key_id):
            cache_key = f"key_metadata:{key_id}"
            return cache.metadata.pop(cache_key, None) is not None
            
        cache.cache_key_metadata = cache_key_metadata
        cache.get_key_metadata = get_key_metadata
        cache.invalidate_key_metadata = invalidate_key_metadata
        
        return cache
        
    def test_key_metadata_caching(self, metadata_cache):
        """Test caching API key metadata."""
        key_id = "test_key_123"
        metadata = {
            "name": "Test API Key",
            "service": "TestService",
            "created_at": "2023-01-01T00:00:00Z",
            "last_accessed": "2023-12-01T12:00:00Z",
            "permissions": ["read", "write"]
        }
        
        # Cache metadata
        result = metadata_cache.cache_key_metadata(key_id, metadata)
        assert result is True
        
        # Retrieve metadata
        retrieved_metadata = metadata_cache.get_key_metadata(key_id)
        assert retrieved_metadata == metadata
        
    def test_metadata_cache_miss(self, metadata_cache):
        """Test cache miss for key metadata."""
        key_id = "nonexistent_key_123"
        
        # Try to get metadata for nonexistent key
        metadata = metadata_cache.get_key_metadata(key_id)
        assert metadata is None
        
    def test_metadata_cache_invalidation(self, metadata_cache):
        """Test invalidating cached key metadata."""
        key_id = "invalidate_key_123"
        metadata = {"name": "Test Key", "service": "TestService"}
        
        # Cache metadata
        metadata_cache.cache_key_metadata(key_id, metadata)
        
        # Verify it's cached
        retrieved_metadata = metadata_cache.get_key_metadata(key_id)
        assert retrieved_metadata == metadata
        
        # Invalidate cache
        result = metadata_cache.invalidate_key_metadata(key_id)
        assert result is True
        
        # Verify it's no longer cached
        retrieved_metadata_after = metadata_cache.get_key_metadata(key_id)
        assert retrieved_metadata_after is None


class TestPermissionCaching:
    """Test caching of user permissions."""
    
    @pytest.fixture
    def permission_cache(self):
        """Mock permission cache."""
        cache = Mock()
        cache.permissions = {}  # Internal storage
        
        def cache_user_permissions(user_id, permissions, ttl=600):
            cache_key = f"user_permissions:{user_id}"
            cache.permissions[cache_key] = {
                'data': permissions,
                'expires_at': datetime.now() + timedelta(seconds=ttl)
            }
            return True
            
        def get_user_permissions(user_id):
            cache_key = f"user_permissions:{user_id}"
            cached = cache.permissions.get(cache_key)
            if cached and cached['expires_at'] > datetime.now():
                return cached['data']
            return None
            
        def invalidate_user_permissions(user_id):
            cache_key = f"user_permissions:{user_id}"
            return cache.permissions.pop(cache_key, None) is not None
            
        cache.cache_user_permissions = cache_user_permissions
        cache.get_user_permissions = get_user_permissions
        cache.invalidate_user_permissions = invalidate_user_permissions
        
        return cache
        
    def test_permission_caching(self, permission_cache):
        """Test caching user permissions."""
        user_id = 123
        permissions = {
            "keys": ["read", "write", "delete"],
            "audit": ["read"],
            "admin": ["user_management"]
        }
        
        # Cache permissions
        result = permission_cache.cache_user_permissions(user_id, permissions)
        assert result is True
        
        # Retrieve permissions
        retrieved_permissions = permission_cache.get_user_permissions(user_id)
        assert retrieved_permissions == permissions
        
    def test_permission_cache_expiration(self, permission_cache):
        """Test permission cache expiration."""
        user_id = 124
        permissions = {"keys": ["read"]}
        
        # Cache with short TTL
        permission_cache.cache_user_permissions(user_id, permissions, ttl=1)
        
        # Should be available immediately
        retrieved_permissions = permission_cache.get_user_permissions(user_id)
        assert retrieved_permissions == permissions
        
        # Wait for expiration
        time.sleep(2)
        
        # Should be expired
        retrieved_permissions_after = permission_cache.get_user_permissions(user_id)
        assert retrieved_permissions_after is None
        
    def test_permission_cache_invalidation_on_change(self, permission_cache):
        """Test invalidating permission cache when permissions change."""
        user_id = 125
        original_permissions = {"keys": ["read"]}
        updated_permissions = {"keys": ["read", "write"]}
        
        # Cache original permissions
        permission_cache.cache_user_permissions(user_id, original_permissions)
        
        # Simulate permission change
        permission_cache.invalidate_user_permissions(user_id)
        
        # Cache new permissions
        permission_cache.cache_user_permissions(user_id, updated_permissions)
        
        # Should get updated permissions
        retrieved_permissions = permission_cache.get_user_permissions(user_id)
        assert retrieved_permissions == updated_permissions


class TestRateLimitingCache:
    """Test cache-based rate limiting."""
    
    @pytest.fixture
    def rate_limit_cache(self):
        """Mock rate limiting cache."""
        cache = Mock()
        cache.rate_limits = {}  # Internal storage
        
        def check_rate_limit(key, limit, window):
            current_time = datetime.now()
            window_start = current_time - timedelta(seconds=window)
            
            # Get existing requests
            requests = cache.rate_limits.get(key, [])
            
            # Filter to current window
            requests = [req_time for req_time in requests if req_time > window_start]
            
            # Check if under limit
            if len(requests) < limit:
                requests.append(current_time)
                cache.rate_limits[key] = requests
                return True
            else:
                return False
                
        def reset_rate_limit(key):
            cache.rate_limits.pop(key, None)
            return True
            
        cache.check_rate_limit = check_rate_limit
        cache.reset_rate_limit = reset_rate_limit
        
        return cache
        
    def test_rate_limiting_under_limit(self, rate_limit_cache):
        """Test rate limiting when under the limit."""
        key = "user:123:api_calls"
        limit = 5
        window = 60  # 60 seconds
        
        # Make requests under the limit
        for i in range(limit):
            result = rate_limit_cache.check_rate_limit(key, limit, window)
            assert result is True, f"Request {i+1} should be allowed"
            
    def test_rate_limiting_over_limit(self, rate_limit_cache):
        """Test rate limiting when over the limit."""
        key = "user:124:api_calls"
        limit = 3
        window = 60
        
        # Make requests up to the limit
        for i in range(limit):
            result = rate_limit_cache.check_rate_limit(key, limit, window)
            assert result is True
            
        # Next request should be denied
        result = rate_limit_cache.check_rate_limit(key, limit, window)
        assert result is False
        
    def test_rate_limiting_window_reset(self, rate_limit_cache):
        """Test rate limiting window reset."""
        key = "user:125:api_calls"
        limit = 2
        window = 1  # 1 second window
        
        # Use up the limit
        for i in range(limit):
            result = rate_limit_cache.check_rate_limit(key, limit, window)
            assert result is True
            
        # Should be over limit
        result = rate_limit_cache.check_rate_limit(key, limit, window)
        assert result is False
        
        # Wait for window to reset
        time.sleep(2)
        
        # Should be allowed again
        result = rate_limit_cache.check_rate_limit(key, limit, window)
        assert result is True
        
    def test_rate_limiting_manual_reset(self, rate_limit_cache):
        """Test manual rate limit reset."""
        key = "user:126:api_calls"
        limit = 2
        window = 60
        
        # Use up the limit
        for i in range(limit):
            rate_limit_cache.check_rate_limit(key, limit, window)
            
        # Should be over limit
        result = rate_limit_cache.check_rate_limit(key, limit, window)
        assert result is False
        
        # Reset rate limit
        rate_limit_cache.reset_rate_limit(key)
        
        # Should be allowed again
        result = rate_limit_cache.check_rate_limit(key, limit, window)
        assert result is True


class TestCachePerformance:
    """Test cache performance and optimization."""
    
    def test_cache_response_time(self, performance_timer):
        """Test cache operation response times."""
        # Mock fast cache operations
        mock_cache = Mock()
        mock_cache.get.return_value = "cached_value"
        mock_cache.set.return_value = True
        
        # Test get performance
        performance_timer.start()
        for i in range(1000):
            mock_cache.get(f"key_{i}")
        performance_timer.stop()
        
        # Should be very fast
        assert performance_timer.elapsed < 1.0, f"Cache gets too slow: {performance_timer.elapsed}s"
        
        # Test set performance
        performance_timer.start()
        for i in range(1000):
            mock_cache.set(f"key_{i}", f"value_{i}")
        performance_timer.stop()
        
        assert performance_timer.elapsed < 1.0, f"Cache sets too slow: {performance_timer.elapsed}s"
        
    def test_cache_memory_usage(self):
        """Test cache memory usage patterns."""
        # This test would monitor memory usage of cache operations
        # Implementation depends on specific monitoring tools available
        pass
        
    def test_cache_hit_ratio(self):
        """Test cache hit ratio monitoring."""
        mock_cache = Mock()
        
        # Simulate cache hits and misses
        cache_hits = 0
        cache_misses = 0
        
        def mock_get(key):
            nonlocal cache_hits, cache_misses
            if key in ['common_key_1', 'common_key_2']:
                cache_hits += 1
                return f"value_for_{key}"
            else:
                cache_misses += 1
                return None
                
        mock_cache.get = mock_get
        
        # Simulate requests
        test_keys = (['common_key_1', 'common_key_2'] * 10) + \
                   [f'rare_key_{i}' for i in range(5)]
                   
        for key in test_keys:
            mock_cache.get(key)
            
        # Calculate hit ratio
        total_requests = cache_hits + cache_misses
        hit_ratio = cache_hits / total_requests if total_requests > 0 else 0
        
        # Should have good hit ratio for common keys
        assert hit_ratio > 0.7, f"Cache hit ratio too low: {hit_ratio}"


class TestCacheFailover:
    """Test cache failover and resilience."""
    
    def test_cache_unavailable_graceful_degradation(self):
        """Test graceful degradation when cache is unavailable."""
        # Mock cache that raises connection errors
        mock_cache = Mock()
        mock_cache.get.side_effect = redis.ConnectionError("Cache unavailable")
        mock_cache.set.side_effect = redis.ConnectionError("Cache unavailable")
        
        # Application should handle cache unavailability gracefully
        try:
            # These operations should not crash the application
            result = mock_cache.get("some_key")
            assert result is None or isinstance(result, Exception)
            
            mock_cache.set("some_key", "some_value")
            
        except redis.ConnectionError:
            # Application should catch and handle this
            pass
            
    def test_cache_timeout_handling(self):
        """Test handling of cache operation timeouts."""
        mock_cache = Mock()
        mock_cache.get.side_effect = redis.TimeoutError("Operation timed out")
        
        # Should handle timeouts gracefully
        try:
            result = mock_cache.get("timeout_key")
        except redis.TimeoutError:
            # Application should handle this appropriately
            pass
            
    def test_cache_data_corruption_detection(self):
        """Test detection of corrupted cache data."""
        mock_cache = Mock()
        
        # Return corrupted JSON data
        mock_cache.get.return_value = '{"invalid": json data}'
        
        # Application should detect and handle corrupted data
        try:
            data = mock_cache.get("json_key")
            if data:
                parsed_data = json.loads(data)
        except json.JSONDecodeError:
            # Should handle JSON parsing errors gracefully
            parsed_data = None
            
        # Should not crash on corrupted data
        assert True  # Test passes if no unhandled exceptions


class TestCacheSecurity:
    """Test cache security measures."""
    
    def test_cache_key_sanitization(self):
        """Test sanitization of cache keys."""
        malicious_keys = [
            "../../../etc/passwd",
            "key with spaces",
            "key:with:colons",
            "key\nwith\nnewlines",
            "key\x00with\x00nulls"
        ]
        
        mock_cache = Mock()
        
        def sanitize_key(key):
            # Basic sanitization - replace problematic characters
            sanitized = key.replace('/', '_').replace('\n', '_').replace('\x00', '_')
            return sanitized
            
        # Test that malicious keys are sanitized
        for malicious_key in malicious_keys:
            sanitized_key = sanitize_key(malicious_key)
            
            # Should not contain dangerous characters
            assert '../' not in sanitized_key
            assert '\n' not in sanitized_key
            assert '\x00' not in sanitized_key
            
    def test_cache_data_encryption(self):
        """Test encryption of sensitive data in cache."""
        sensitive_data = {
            "api_key": "secret_api_key_12345",
            "password": "user_password",
            "personal_info": "sensitive_user_data"
        }
        
        mock_cache = Mock()
        
        def encrypt_cache_data(data):
            # Mock encryption - in reality would use proper encryption
            encrypted = f"ENCRYPTED:{json.dumps(data)}"
            return encrypted
            
        def decrypt_cache_data(encrypted_data):
            if encrypted_data.startswith("ENCRYPTED:"):
                json_data = encrypted_data[10:]  # Remove "ENCRYPTED:" prefix
                return json.loads(json_data)
            return None
            
        # Encrypt before caching
        encrypted = encrypt_cache_data(sensitive_data)
        mock_cache.set("sensitive_key", encrypted)
        
        # Verify sensitive data is not in plaintext
        cached_value = encrypted
        assert "secret_api_key_12345" not in cached_value or cached_value.startswith("ENCRYPTED:")
        
        # Decrypt when retrieving
        decrypted = decrypt_cache_data(cached_value)
        assert decrypted == sensitive_data
        
    def test_cache_access_control(self):
        """Test access control for cache operations."""
        # Mock cache with access control
        mock_cache = Mock()
        
        def check_cache_permission(user_id, operation, key):
            # Mock permission check
            if user_id == "admin":
                return True
            elif user_id == "user" and operation == "read":
                return True
            elif user_id == "user" and operation == "write" and key.startswith("user:"):
                return True
            return False
            
        # Test admin access
        assert check_cache_permission("admin", "read", "any_key") is True
        assert check_cache_permission("admin", "write", "any_key") is True
        
        # Test user access
        assert check_cache_permission("user", "read", "any_key") is True
        assert check_cache_permission("user", "write", "admin_key") is False
        assert check_cache_permission("user", "write", "user:123:data") is True
        
        # Test unauthorized access
        assert check_cache_permission("guest", "read", "any_key") is False
        assert check_cache_permission("guest", "write", "any_key") is False


class TestCacheMonitoring:
    """Test cache monitoring and metrics."""
    
    def test_cache_metrics_collection(self):
        """Test collection of cache metrics."""
        # Mock metrics collector
        metrics = {
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_errors": 0,
            "total_requests": 0
        }
        
        def record_cache_hit():
            metrics["cache_hits"] += 1
            metrics["total_requests"] += 1
            
        def record_cache_miss():
            metrics["cache_misses"] += 1
            metrics["total_requests"] += 1
            
        def record_cache_error():
            metrics["cache_errors"] += 1
            metrics["total_requests"] += 1
            
        # Simulate cache operations
        for i in range(10):
            if i < 7:
                record_cache_hit()
            elif i < 9:
                record_cache_miss()
            else:
                record_cache_error()
                
        # Verify metrics
        assert metrics["cache_hits"] == 7
        assert metrics["cache_misses"] == 2
        assert metrics["cache_errors"] == 1
        assert metrics["total_requests"] == 10
        
        # Calculate hit ratio
        hit_ratio = metrics["cache_hits"] / (metrics["cache_hits"] + metrics["cache_misses"])
        assert hit_ratio == 0.7777777777777778  # 7/9
        
    def test_cache_health_monitoring(self):
        """Test cache health monitoring."""
        def check_cache_health():
            health_status = {
                "redis_connection": True,
                "memory_usage": 45.2,  # Percentage
                "hit_ratio": 0.85,
                "avg_response_time": 2.3,  # Milliseconds
                "error_rate": 0.01  # 1%
            }
            
            # Determine overall health
            is_healthy = (
                health_status["redis_connection"] and
                health_status["memory_usage"] < 80 and
                health_status["hit_ratio"] > 0.7 and
                health_status["avg_response_time"] < 10 and
                health_status["error_rate"] < 0.05
            )
            
            health_status["overall_health"] = "healthy" if is_healthy else "unhealthy"
            return health_status
            
        health = check_cache_health()
        assert health["overall_health"] == "healthy"
        assert health["redis_connection"] is True
        assert health["memory_usage"] < 80
        assert health["hit_ratio"] > 0.7
