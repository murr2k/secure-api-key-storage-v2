#!/usr/bin/env python3
"""
Check if all required dependencies are installed
"""

import sys
import subprocess

def check_dependencies():
    """Check if all required dependencies are available"""
    print("Checking dependencies for API Key Storage System")
    print("=" * 50)
    
    required = {
        "cryptography": "Core encryption functionality",
        "tabulate": "Formatted table output",
        "psutil": "Performance monitoring"
    }
    
    optional = {
        "pytest": "Alternative test runner",
        "pytest-cov": "Code coverage analysis",
        "black": "Code formatting",
        "flake8": "Code linting",
        "mypy": "Type checking",
        "bandit": "Security linting",
        "safety": "Vulnerability scanning"
    }
    
    missing_required = []
    missing_optional = []
    
    # Check required packages
    print("\nRequired Dependencies:")
    for package, description in required.items():
        try:
            __import__(package)
            print(f"  ✅ {package}: {description}")
        except ImportError:
            print(f"  ❌ {package}: {description}")
            missing_required.append(package)
    
    # Check optional packages
    print("\nOptional Dependencies:")
    for package, description in optional.items():
        try:
            __import__(package.replace("-", "_"))
            print(f"  ✅ {package}: {description}")
        except ImportError:
            print(f"  ⚠️  {package}: {description}")
            missing_optional.append(package)
    
    print("\n" + "="*50)
    
    if missing_required:
        print("❌ Missing REQUIRED dependencies!")
        print("\nTo install required dependencies, run:")
        print("  pip install " + " ".join(missing_required))
        print("\nOr install all dependencies with:")
        print("  pip install -r requirements.txt")
        return False
    else:
        print("✅ All required dependencies are installed!")
        
        if missing_optional:
            print(f"\n⚠️  {len(missing_optional)} optional dependencies are missing.")
            print("These are useful for development but not required for basic usage.")
            print("\nTo install all dependencies:")
            print("  pip install -r requirements.txt")
        else:
            print("✅ All optional dependencies are also installed!")
        
        print("\nYou can now run:")
        print("  python3 validate_system.py    # Quick validation")
        print("  python3 src/user_interface.py # Interactive UI")
        print("  python3 run_tests.py          # Full test suite")
        
        return True


if __name__ == "__main__":
    success = check_dependencies()
    sys.exit(0 if success else 1)