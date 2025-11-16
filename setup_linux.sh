#!/bin/bash
# Charming Hera Setup Script for Linux
# This script installs prerequisites and sets up the SBOM security scanner

set -e  # Exit on any error

echo "🔍 Charming Hera Setup for Linux"
echo "================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  This script should not be run as root (except for package installation)"
   echo "   Run without sudo, the script will ask for sudo when needed."
   exit 1
fi

# Detect Linux distribution
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    INSTALL_CMD="sudo apt update && sudo apt install -y"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf" 
    INSTALL_CMD="sudo dnf install -y"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    INSTALL_CMD="sudo yum install -y"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="sudo pacman -S --noconfirm"
else
    echo "❌ Unsupported Linux distribution. Please install manually:"
    echo "   - Python 3.7+"
    echo "   - Docker"
    exit 1
fi

echo "📦 Detected package manager: $PKG_MANAGER"

# Check Python 3
echo "🐍 Checking Python 3..."
if command -v python3 >/dev/null 2>&1; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo "✅ Python $PYTHON_VERSION found"
else
    echo "📥 Installing Python 3..."
    if [[ $PKG_MANAGER == "apt" ]]; then
        $INSTALL_CMD python3 python3-pip
    elif [[ $PKG_MANAGER == "dnf" || $PKG_MANAGER == "yum" ]]; then
        $INSTALL_CMD python3 python3-pip
    elif [[ $PKG_MANAGER == "pacman" ]]; then
        $INSTALL_CMD python
    fi
fi

# Check Docker
echo "🐳 Checking Docker..."
if command -v docker >/dev/null 2>&1; then
    echo "✅ Docker found"
else
    echo "📥 Installing Docker..."
    if [[ $PKG_MANAGER == "apt" ]]; then
        $INSTALL_CMD docker.io
    elif [[ $PKG_MANAGER == "dnf" ]]; then
        $INSTALL_CMD docker
    elif [[ $PKG_MANAGER == "yum" ]]; then
        $INSTALL_CMD docker
    elif [[ $PKG_MANAGER == "pacman" ]]; then
        $INSTALL_CMD docker
    fi
fi

# Start Docker service
echo "🚀 Starting Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
echo "👤 Adding user to docker group..."
sudo usermod -a -G docker $USER

# Make script executable
echo "🔧 Making scripts executable..."
chmod +x sbom_scanner.py 2>/dev/null || true
chmod +x export_findings.py 2>/dev/null || true

# Build Docker image
echo "🏗️  Building scanner Docker image..."
if [[ -d "scanner" ]]; then
    docker build -t sbom_scanner_image:latest ./scanner
    echo "✅ Docker image built successfully"
else
    echo "❌ Scanner directory not found. Make sure you're in the project root."
    exit 1
fi

# Test the setup
echo "🧪 Testing setup..."
if ./sbom_scanner.py --help >/dev/null 2>&1; then
    echo "✅ Scanner is working"
elif python3 sbom_scanner.py --help >/dev/null 2>&1; then
    echo "✅ Scanner is working (use python3 command)"
else
    echo "❌ Scanner test failed"
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📝 Next steps:"
echo "   1. Log out and back in (for docker group changes)"
echo "   2. Test: python3 sbom_scanner.py --help"
echo "   3. Run: python3 sbom_scanner.py --sbom sample_sbom.json --show-results"
echo ""
echo "💡 Tip: If you get docker permission errors, run 'newgrp docker'"