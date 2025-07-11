#!/usr/bin/env python3
"""
Simple script to run the backend with environment variables loaded
"""

import os
import subprocess
import sys
from pathlib import Path

# Change to backend directory
backend_dir = Path(__file__).parent
os.chdir(backend_dir)

# Check if .env exists
if not Path('.env').exists():
    print("Error: .env file not found!")
    print("Creating .env from .env.example...")
    
    # Copy .env.example to .env
    import shutil
    shutil.copy('.env.example', '.env')
    
    print("\nPlease edit .env and set:")
    print("  API_KEY_MASTER=your-master-password")
    print("\nThen run this script again.")
    sys.exit(1)

# Load and display environment variables
from dotenv import load_dotenv
load_dotenv()

print("=" * 50)
print("Starting Backend with Environment:")
print("=" * 50)
print(f"API_KEY_MASTER: {'SET' if os.environ.get('API_KEY_MASTER') else 'NOT SET'}")
print(f"JWT_SECRET_KEY: {'SET' if os.environ.get('JWT_SECRET_KEY') else 'NOT SET'}")
print(f"CORS_ORIGINS: {os.environ.get('CORS_ORIGINS', 'http://localhost:3000')}")
print("=" * 50)

if not os.environ.get('API_KEY_MASTER'):
    print("\nERROR: API_KEY_MASTER not set in .env file!")
    print("Please edit .env and set your master password.")
    sys.exit(1)

# Run uvicorn
print("\nStarting FastAPI server...")
subprocess.run([
    sys.executable, "-m", "uvicorn", 
    "main:app", 
    "--reload", 
    "--host", "0.0.0.0", 
    "--port", "8000"
])