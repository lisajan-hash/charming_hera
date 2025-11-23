#!/bin/bash
# Charming Hera Setup Script for Linux
# This script installs prerequisites and sets up the SBOM security scanner

set -e  # Exit on any error

echo "🔍 Charming Hera Setup for Linux"
echo "================================="

# Flags
SKIP_INSTALL=false
DEBUG=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-install)
            SKIP_INSTALL=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [[ $DEBUG == true ]]; then
    echo "🔧 Debug info (early):"
    echo "PATH=$PATH"
    echo "which apt-get: $(command -v apt-get || true)"
    echo "which dnf: $(command -v dnf || true)"
    echo "which yum: $(command -v yum || true)"
    echo "which pacman: $(command -v pacman || true)"
    echo "which apk: $(command -v apk || true)"
    echo "which zypper: $(command -v zypper || true)"
    echo "which python3: $(command -v python3 || command -v python || true)"
    echo "python version: $( (command -v python3 && python3 --version) || (command -v python && python --version) || true)"
    echo "which docker: $(command -v docker || true)"
    echo "which podman: $(command -v podman || true)"
    echo "which curl: $(command -v curl || true)"
    echo "which wget: $(command -v wget || true)"
    echo "docker in /snap/bin: $([[ -x /snap/bin/docker ]] && echo yes || echo no)"
    echo "docker in /usr/local/bin: $([[ -x /usr/local/bin/docker ]] && echo yes || echo no)"
    echo "docker in /usr/bin: $([[ -x /usr/bin/docker ]] && echo yes || echo no)"
    echo "docker in /bin: $([[ -x /bin/docker ]] && echo yes || echo no)"
    echo "docker in /sbin: $([[ -x /sbin/docker ]] && echo yes || echo no)"
    echo "docker in /opt/bin: $([[ -x /opt/bin/docker ]] && echo yes || echo no)"
fi

# If running as root, print a warning but continue (we use sudo only when needed)
if [[ $EUID -eq 0 ]]; then
     echo "⚠️  You are running this script as root — the script will still work but we recommend running as a normal user."
fi

# Helper to run a command with privilege if possible
run_privileged() {
    if command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    elif [ "$EUID" -eq 0 ]; then
        "$@"
    elif command -v su >/dev/null 2>&1; then
        su -c "$*"
    else
        echo "⚠️  No sudo or su available; attempting to run without elevation: $*"
        "$@"
    fi
}

# Detect Linux distribution
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt update && apt install -y"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf" 
    INSTALL_CMD="dnf install -y"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    INSTALL_CMD="yum install -y"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="pacman -S --noconfirm"
elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
    INSTALL_CMD="apk add --no-cache"
elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
    INSTALL_CMD="zypper install -y"
else
    # No supported package manager detected
    if [[ $SKIP_INSTALL == true ]]; then
        echo "⚠️  Could not detect package manager, but continuing (--skip-install set)."
        PKG_MANAGER="none"
        INSTALL_CMD="echo 'Skipping install - no package manager detected'"
    else
        # Check if Python is available (Docker will be installed later if needed)
        if command -v python3 >/dev/null 2>&1; then
            PKG_MANAGER="none"
            INSTALL_CMD="echo 'No package manager - skipping installs'"
            echo "⚠️  No supported package manager found, but Python is installed; proceeding (Docker will be installed automatically)."
        else
            echo "❌ Unsupported Linux distribution or missing prerequisites."
            echo "   Please install manually:"
            echo "   - Python 3.7+ (found: no)"
            echo "   - Docker (or Podman) (will be installed automatically if Python is available)"
            echo ""
            echo "   Installation commands (choose your distro):"
            echo "   - Ubuntu/Debian: sudo apt update && sudo apt install -y python3 python3-pip docker.io"
            echo "   - Fedora/CentOS: sudo dnf install -y python3 python3-pip docker"
            echo "   - Arch: sudo pacman -Syu --noconfirm python python-pip docker"
            echo "   - Alpine: sudo apk add --no-cache python3 py3-pip docker"
            echo "   - SUSE: sudo zypper install -y python3 python3-pip docker"
            echo ""
            echo "   Or re-run with --skip-install to continue without package installation (requires tools already installed)"
            exit 1
        fi
    fi
fi

echo "📦 Detected package manager: $PKG_MANAGER"

# Check Python 3
echo "🐍 Checking Python 3..."
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    # Ensure python is v3
    PY_VER=$(python --version 2>&1 | awk '{print $2}')
    if [[ $PY_VER == 3.* ]]; then
        PYTHON_CMD="python"
    fi
fi
if [[ -n "$PYTHON_CMD" ]]; then
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
    echo "✅ $PYTHON_CMD $PYTHON_VERSION found"
else
    echo "📥 Installing Python 3..."
    if [[ $SKIP_INSTALL == true ]]; then
        echo "⚠️  Skipping installation of Python packages (user requested --skip-install)"
    else
        if [[ $PKG_MANAGER == "apt" ]]; then
            run_privileged apt update
            run_privileged apt install -y python3 python3-pip
        elif [[ $PKG_MANAGER == "dnf" || $PKG_MANAGER == "yum" ]]; then
            run_privileged $PKG_MANAGER install -y python3 python3-pip
        elif [[ $PKG_MANAGER == "pacman" ]]; then
            run_privileged pacman -Syu --noconfirm python
        elif [[ $PKG_MANAGER == "apk" ]]; then
            run_privileged apk add --no-cache python3 python3-dev py3-pip
        elif [[ $PKG_MANAGER == "zypper" ]]; then
            run_privileged zypper install -y python3 python3-pip
        fi
    fi
fi

# Detect available container runtime (Docker or Podman)
# Allow user to override via environment variable DOCKER_CMD if available
if [[ -n "$DOCKER_CMD" && ( -x "$(command -v $DOCKER_CMD 2>/dev/null)" ) ]]; then
    echo "Using container runtime from DOCKER_CMD environment variable: $DOCKER_CMD"
else
    DOCKER_CMD=""
    if command -v docker >/dev/null 2>&1; then
    DOCKER_CMD="docker"
elif command -v podman >/dev/null 2>&1; then
    DOCKER_CMD="podman"
else
    # Check common locations for docker binary (snap, /usr/local/bin, etc.)
    if [[ -x "/snap/bin/docker" ]]; then
        DOCKER_CMD="/snap/bin/docker"
    elif [[ -x "/usr/local/bin/docker" ]]; then
        DOCKER_CMD="/usr/local/bin/docker"
    elif [[ -x "/usr/bin/docker" ]]; then
        DOCKER_CMD="/usr/bin/docker"
    elif [[ -x "/bin/docker" ]]; then
        DOCKER_CMD="/bin/docker"
    elif [[ -x "/sbin/docker" ]]; then
        DOCKER_CMD="/sbin/docker"
    elif [[ -x "/opt/bin/docker" ]]; then
        DOCKER_CMD="/opt/bin/docker"
    fi
    fi
fi

echo "🐳 Checking container runtime (Docker/Podman)..."
if [[ -n "$DOCKER_CMD" ]]; then
    echo "✅ $DOCKER_CMD found"
else
    echo "📥 Installing Docker..."
    if [[ $SKIP_INSTALL == true ]]; then
        echo "⚠️  Skipping Docker installation (--skip-install set)"
    else
        # Check if we can run commands as root
        if ! run_privileged id -u 2>/dev/null | grep -q '^0$'; then
            echo "❌ Cannot run commands as root (no sudo/su/root access), cannot install Docker automatically."
            echo "   Please install Docker manually or run this script as root."
            exit 1
        fi
        if [[ $PKG_MANAGER != "none" ]]; then
            if [[ $PKG_MANAGER == "apt" ]]; then
                run_privileged apt update
                run_privileged apt install -y docker.io
            elif [[ $PKG_MANAGER == "dnf" ]]; then
                run_privileged dnf install -y docker
            elif [[ $PKG_MANAGER == "yum" ]]; then
                run_privileged yum install -y docker
            elif [[ $PKG_MANAGER == "pacman" ]]; then
                run_privileged pacman -S --noconfirm docker
            elif [[ $PKG_MANAGER == "apk" ]]; then
                run_privileged apk add --no-cache docker
            elif [[ $PKG_MANAGER == "zypper" ]]; then
                run_privileged zypper install -y docker
            fi
            else
                # No package manager, try get-docker.sh
                if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
                    echo "Attempting to install Docker using official script..."
                    if command -v curl >/dev/null 2>&1; then
                        curl -fsSL https://get.docker.com -o get-docker.sh || { echo "❌ Failed to download Docker install script (check internet connection)"; rm -f get-docker.sh; exit 1; }
                    else
                        wget -q https://get.docker.com -O get-docker.sh || { echo "❌ Failed to download Docker install script (check internet connection)"; rm -f get-docker.sh; exit 1; }
                    fi
                    sh get-docker.sh || { echo "❌ Failed to run Docker install script (likely no root access or unsupported system)"; rm -f get-docker.sh; exit 1; }
                    rm -f get-docker.sh
                    # Check if installed
                    if command -v docker >/dev/null 2>&1; then
                        DOCKER_CMD="docker"
                        echo "✅ Docker installed successfully"
                    else
                        echo "❌ Docker install script ran but docker command not found in PATH"
                        exit 1
                    fi
                else
                    echo "❌ No package manager and no curl/wget available to install Docker"
                    exit 1
                fi
            fi
    fi
fi

# Start Docker service
echo "🚀 Starting Docker service..."
if command -v systemctl >/dev/null 2>&1; then
    if [[ $SKIP_INSTALL == true ]]; then
            echo "⚠️  Skipping start/enabling docker because --skip-install was set"
    else
            run_privileged systemctl start docker || echo "⚠️  systemctl failed to start docker; try starting manually"
            run_privileged systemctl enable docker || true
    fi
else
    echo "⚠️  systemctl not present on this system; attempting 'service docker start'"
    run_privileged service docker start || echo "⚠️  Could not start docker service via 'service' either"
fi

# Add user to docker group
echo "👤 Adding user to docker group (if applicable)..."
if command -v usermod >/dev/null 2>&1; then
    run_privileged usermod -a -G docker $USER || echo "⚠️  Could not add user to docker group; run as root or ask admin"
else
    echo "⚠️  usermod not available on this platform; skip adding group."
fi

# Make script executable
echo "🔧 Making scripts executable..."
chmod +x sbom_scanner.py 2>/dev/null || true
chmod +x export_findings.py 2>/dev/null || true

# Build Docker image
echo "🏗️  Building scanner Docker image..."
if [[ -d "scanner" ]]; then
    if [[ -n "$DOCKER_CMD" ]]; then
        $DOCKER_CMD build -t sbom_scanner_image:latest ./scanner
    else
        echo "❌ No container runtime (docker/podman) found — cannot build the scanner image"
        exit 1
    fi
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