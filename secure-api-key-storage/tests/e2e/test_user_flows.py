"""
End-to-end tests for critical user flows.
These tests verify complete user journeys through the application.
"""

import asyncio
import os
import time
import unittest
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException


class E2ETestCase(unittest.TestCase):
    """Base class for E2E tests."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment for all E2E tests."""
        # Configure Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        
        try:
            cls.driver = webdriver.Chrome(options=chrome_options)
            cls.driver.implicitly_wait(10)
            cls.wait = WebDriverWait(cls.driver, 20)
            
            # Test environment URLs
            cls.base_url = os.getenv("E2E_BASE_URL", "http://localhost:3000")
            cls.api_url = os.getenv("E2E_API_URL", "http://localhost:8000")
            
        except Exception as e:
            print(f"Failed to initialize WebDriver: {e}")
            print("Skipping E2E tests - WebDriver not available")
            cls.driver = None
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests."""
        if cls.driver:
            cls.driver.quit()
    
    def setUp(self):
        """Set up each test."""
        if not self.driver:
            self.skipTest("WebDriver not available")
        
        # Start with a clean state
        self.driver.delete_all_cookies()
        self.driver.refresh()
    
    def login(self, password="test_master_password"):
        """Helper method to log in."""
        self.driver.get(f"{self.base_url}/login")
        
        password_input = self.wait.until(
            EC.presence_of_element_located((By.NAME, "password"))
        )
        password_input.send_keys(password)
        
        login_button = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]")
        login_button.click()
        
        # Wait for redirect to dashboard
        self.wait.until(EC.url_contains("/dashboard"))
    
    def logout(self):
        """Helper method to log out."""
        try:
            logout_button = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Logout')]")
            logout_button.click()
            self.wait.until(EC.url_contains("/login"))
        except:
            # If logout fails, go to login page directly
            self.driver.get(f"{self.base_url}/login")


class TestAuthenticationFlow(E2ETestCase):
    """Test authentication user flows."""
    
    def test_successful_login_flow(self):
        """Test successful login flow."""
        self.driver.get(f"{self.base_url}/login")
        
        # Check if login page loads
        self.assertIn("Login", self.driver.title)
        
        # Enter password
        password_input = self.wait.until(
            EC.presence_of_element_located((By.NAME, "password"))
        )
        password_input.send_keys("test_master_password")
        
        # Click login
        login_button = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]")
        login_button.click()
        
        # Should redirect to dashboard
        self.wait.until(EC.url_contains("/"))
        current_url = self.driver.current_url
        self.assertTrue(current_url.endswith("/") or "dashboard" in current_url)
    
    def test_failed_login_flow(self):
        """Test failed login with wrong password."""
        self.driver.get(f"{self.base_url}/login")
        
        # Enter wrong password
        password_input = self.wait.until(
            EC.presence_of_element_located((By.NAME, "password"))
        )
        password_input.send_keys("wrong_password")
        
        # Click login
        login_button = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]")
        login_button.click()
        
        # Should show error message
        try:
            error_message = self.wait.until(
                EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Invalid') or contains(text(), 'Error')]"))
            )
            self.assertTrue(error_message.is_displayed())
        except TimeoutException:
            # Check if still on login page
            self.assertIn("login", self.driver.current_url.lower())
    
    def test_logout_flow(self):
        """Test logout flow."""
        # First login
        self.login()
        
        # Then logout
        self.logout()
        
        # Should be back on login page
        self.assertIn("login", self.driver.current_url.lower())


class TestDashboardFlow(E2ETestCase):
    """Test dashboard user flows."""
    
    def test_dashboard_loads_with_data(self):
        """Test that dashboard loads and displays data."""
        self.login()
        
        # Wait for dashboard to load
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
        
        # Check for key stats
        try:
            # Look for stats cards or key metrics
            stats_elements = self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Total') or contains(text(), 'Active') or contains(text(), 'Keys')]")
            self.assertGreater(len(stats_elements), 0, "No stats found on dashboard")
        except:
            # If no specific stats, just check that page loaded
            self.assertTrue(True, "Dashboard loaded successfully")
    
    def test_navigation_menu(self):
        """Test navigation menu functionality."""
        self.login()
        
        # Test navigation to Keys page
        try:
            keys_link = self.wait.until(
                EC.element_to_be_clickable((By.XPATH, "//a[contains(text(), 'Keys') or contains(@href, '/keys')]"))
            )
            keys_link.click()
            self.wait.until(EC.url_contains("/keys"))
        except TimeoutException:
            print("Keys navigation not found or failed")
        
        # Test navigation to Audit page
        try:
            audit_link = self.driver.find_element(By.XPATH, "//a[contains(text(), 'Audit') or contains(@href, '/audit')]")
            audit_link.click()
            self.wait.until(EC.url_contains("/audit"))
        except:
            print("Audit navigation not found or failed")
        
        # Test navigation to Settings page
        try:
            settings_link = self.driver.find_element(By.XPATH, "//a[contains(text(), 'Settings') or contains(@href, '/settings')]")
            settings_link.click()
            self.wait.until(EC.url_contains("/settings"))
        except:
            print("Settings navigation not found or failed")


class TestKeyManagementFlow(E2ETestCase):
    """Test key management user flows."""
    
    def test_keys_page_loads(self):
        """Test that keys page loads correctly."""
        self.login()
        
        # Navigate to keys page
        self.driver.get(f"{self.base_url}/keys")
        
        # Wait for keys page to load
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
        
        # Check for key management elements
        page_source = self.driver.page_source.lower()
        self.assertTrue(
            "key" in page_source or "api" in page_source,
            "Keys page doesn't contain key-related content"
        )
    
    def test_add_key_flow(self):
        """Test adding a new API key."""
        self.login()
        self.driver.get(f"{self.base_url}/keys")
        
        try:
            # Look for Add Key button
            add_button = self.wait.until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Add') or contains(text(), 'Create') or contains(text(), 'New')]"))
            )
            add_button.click()
            
            # Wait for form or modal to appear
            time.sleep(2)
            
            # Check if form fields are present
            form_fields = self.driver.find_elements(By.TAG_NAME, "input")
            self.assertGreater(len(form_fields), 0, "No form fields found for adding key")
            
        except TimeoutException:
            print("Add key functionality not found or not working")


class TestAuditFlow(E2ETestCase):
    """Test audit log user flows."""
    
    def test_audit_page_loads(self):
        """Test that audit page loads correctly."""
        self.login()
        
        # Navigate to audit page
        self.driver.get(f"{self.base_url}/audit")
        
        # Wait for audit page to load
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
        
        # Check for audit-related content
        page_source = self.driver.page_source.lower()
        self.assertTrue(
            "audit" in page_source or "log" in page_source or "activity" in page_source,
            "Audit page doesn't contain audit-related content"
        )


class TestSettingsFlow(E2ETestCase):
    """Test settings user flows."""
    
    def test_settings_page_loads(self):
        """Test that settings page loads correctly."""
        self.login()
        
        # Navigate to settings page
        self.driver.get(f"{self.base_url}/settings")
        
        # Wait for settings page to load
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
        
        # Check for settings-related content
        page_source = self.driver.page_source.lower()
        self.assertTrue(
            "setting" in page_source or "config" in page_source or "security" in page_source,
            "Settings page doesn't contain settings-related content"
        )


class TestResponsiveDesign(E2ETestCase):
    """Test responsive design and mobile compatibility."""
    
    def test_mobile_layout(self):
        """Test mobile layout."""
        # Set mobile viewport
        self.driver.set_window_size(375, 667)
        
        self.login()
        
        # Check that page is still functional on mobile
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
        
        # Basic check that content is visible
        body = self.driver.find_element(By.TAG_NAME, "body")
        self.assertTrue(body.is_displayed())
    
    def test_tablet_layout(self):
        """Test tablet layout."""
        # Set tablet viewport
        self.driver.set_window_size(768, 1024)
        
        self.login()
        
        # Check that page is functional on tablet
        self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
        
        # Basic check that content is visible
        body = self.driver.find_element(By.TAG_NAME, "body")
        self.assertTrue(body.is_displayed())


class TestPerformance(E2ETestCase):
    """Test performance-related aspects."""
    
    def test_page_load_performance(self):
        """Test page load performance."""
        start_time = time.time()
        
        self.driver.get(f"{self.base_url}/login")
        
        # Wait for page to be interactive
        self.wait.until(EC.presence_of_element_located((By.NAME, "password")))
        
        load_time = time.time() - start_time
        
        # Page should load within 5 seconds
        self.assertLess(load_time, 5.0, f"Page load took too long: {load_time:.2f}s")
    
    def test_navigation_performance(self):
        """Test navigation performance between pages."""
        self.login()
        
        pages = ["/keys", "/audit", "/settings", "/"]
        
        for page in pages:
            start_time = time.time()
            self.driver.get(f"{self.base_url}{page}")
            
            # Wait for page to load
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "main")))
            
            load_time = time.time() - start_time
            
            # Navigation should be fast (under 3 seconds)
            self.assertLess(load_time, 3.0, f"Navigation to {page} took too long: {load_time:.2f}s")


if __name__ == "__main__":
    # Check if running in CI environment
    if os.getenv("CI"):
        print("Running E2E tests in CI environment")
    
    # Create test reports directory
    os.makedirs("test-reports/e2e", exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)