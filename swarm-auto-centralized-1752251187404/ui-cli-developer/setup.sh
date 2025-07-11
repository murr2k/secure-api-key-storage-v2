#!/bin/bash
# Secure Key Manager Setup Script

echo "======================================"
echo "Secure Key Manager Installation"
echo "======================================"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo "Error: Python $REQUIRED_VERSION or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

echo "✓ Python version check passed: $PYTHON_VERSION"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip

# Create requirements file
cat > requirements.txt << EOF
click>=8.0.0
rich>=13.0.0
cryptography>=41.0.0
pyperclip>=1.8.0
EOF

pip install -r requirements.txt

# Make CLI executable
chmod +x key-manager-cli.py

# Create wrapper script
cat > key-manager << 'EOF'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/venv/bin/activate"
python "$SCRIPT_DIR/key-manager-cli.py" "$@"
EOF

chmod +x key-manager

# Create systemd user service (optional)
mkdir -p ~/.config/systemd/user/

cat > ~/.config/systemd/user/key-manager-agent.service << EOF
[Unit]
Description=Secure Key Manager Agent
After=network.target

[Service]
Type=simple
ExecStart=$(pwd)/key-manager agent
Restart=on-failure

[Install]
WantedBy=default.target
EOF

echo ""
echo "======================================"
echo "Installation Complete!"
echo "======================================"
echo ""
echo "To get started:"
echo "1. Run: ./key-manager wizard"
echo "   This will guide you through initial setup"
echo ""
echo "2. Or run: ./key-manager setup"
echo "   To manually initialize with a master password"
echo ""
echo "3. Add to PATH (optional):"
echo "   echo 'export PATH=\"$(pwd):\$PATH\"' >> ~/.bashrc"
echo "   source ~/.bashrc"
echo ""
echo "For help: ./key-manager --help"