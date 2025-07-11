#!/usr/bin/env python3
"""
Test script to verify dashboard authentication
"""

import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('backend/.env')

# Backend URL
BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/api/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.json()

def test_login(password):
    """Test login endpoint"""
    print(f"\nTesting login with password: {password[:3]}...")
    
    # Send as form data (OAuth2PasswordRequestForm expects this)
    data = {
        'username': 'admin',
        'password': password,
        'grant_type': 'password'  # OAuth2 requires this
    }
    
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        data=data,  # Use data, not json
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print("✓ Login successful!")
        tokens = response.json()
        print(f"Access token: {tokens['access_token'][:20]}...")
        return tokens
    else:
        print(f"✗ Login failed: {response.text}")
        return None

def test_authenticated_request(access_token):
    """Test an authenticated request"""
    print("\nTesting authenticated request...")
    
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(
        f"{BASE_URL}/api/keys",
        headers=headers
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print("✓ Authenticated request successful!")
        print(f"Keys: {response.json()}")
    else:
        print(f"✗ Request failed: {response.text}")

if __name__ == "__main__":
    print("Dashboard Authentication Test")
    print("=" * 50)
    
    # Check environment
    master_password = os.environ.get('API_KEY_MASTER')
    if not master_password:
        print("ERROR: API_KEY_MASTER not set in backend/.env")
        exit(1)
    
    print(f"Master password from env: {master_password[:3]}...")
    
    # Test health
    health = test_health()
    
    if not health.get('master_password_set'):
        print("\nERROR: Backend doesn't see the master password!")
        print("Make sure to:")
        print("1. Edit backend/.env file")
        print("2. Set API_KEY_MASTER=your-password")
        print("3. Restart the backend")
        exit(1)
    
    # Test login
    tokens = test_login(master_password)
    
    if tokens:
        # Test authenticated request
        test_authenticated_request(tokens['access_token'])
    
    print("\n" + "=" * 50)
    print("Test complete!")
    
    print("\nTroubleshooting tips:")
    print("1. Make sure backend is running: cd dashboard/backend && ./start.sh")
    print("2. Make sure frontend is running: cd dashboard/frontend && npm run dev")
    print("3. Check backend/.env has API_KEY_MASTER set")
    print("4. Try accessing http://localhost:8000/docs for API documentation")