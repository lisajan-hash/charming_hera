<div align="center">

# Charming Hera

<img src="logo.png" alt="Charming Hera Logo" width="200"/>

**SBOM Security Scanner**

*A comprehensive supply chain security scanner that analyzes Software Bill of Materials (SBOM) files to detect potential threats in Node.js (npm) and Python (PyPI) packages.*

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](README.md)
[![Docker](https://img.shields.io/badge/docker-required-blue)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)

</div>

---

## Overview

Charming Hera installs packages in isolated Docker containers and performs deep analysis for suspicious code patterns, malicious behaviors, and supply chain attacks.

## Features

🔍 **Deep Package Analysis**: Installs and scans actual package code in isolated containers  
🎯 **Advanced Detection**: 8 categories of threats with 40+ detection rules  
📄 **Content Extraction**: Captures exact code snippets where threats are detected  
🛡️ **Container Isolation**: Safe analysis environment prevents host contamination  
📊 **Comprehensive Reporting**: Detailed findings with context and evidence  
🎨 **Colorized Output**: Beautiful terminal interface with status colors and icons  
💾 **Database Storage**: SQLite database with deduplication and history tracking  

## Quick Start

### Prerequisites

#### Windows
- **Docker Desktop** installed and running
- **Python 3.7+** available in PATH
- **Windows PowerShell** or **Command Prompt**

#### Linux
- **Docker** installed and running
- **Python 3.7+** installed
- **bash** shell (or compatible shell)

### Installation

#### Option 1: Automated Setup (Recommended)

**Windows:**
```powershell
# Run PowerShell as Administrator
cd "C:\path\to\charming_hera"
.\setup_windows.ps1
```

**Linux:**
```bash
cd /path/to/charming_hera
chmod +x setup_linux.sh
./setup_linux.sh
```

Note: If the script reports "Unsupported Linux distribution", you can either install Python 3.7+ and Docker manually as shown in the Manual Setup section below, or run the installer without attempting package installs and with the Bash interpreter:

```bash
# Run non-install steps only (useful in minimal/distroless environments or when sudo is not available)
bash setup_linux.sh --skip-install
```

#### Option 2: Manual Setup

**Windows:**
```powershell
# Ensure Docker Desktop is running
docker --version

# Clone or download the project
cd "C:\path\to\charming_hera"

# Build the scanner Docker image
docker build -t sbom_scanner_image:latest .\scanner
```

**Linux:**
```bash
# Install prerequisites (Ubuntu/Debian)
sudo apt update
sudo apt install python3 python3-pip docker.io

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (requires logout/login)
sudo usermod -a -G docker $USER

# For RHEL/CentOS/Fedora
# sudo dnf install python3 python3-pip docker

# Clone or download the project
cd /path/to/charming_hera

# Make script executable (optional)
chmod +x sbom_scanner.py

# Build the scanner Docker image
docker build -t sbom_scanner_image:latest ./scanner
```

### Basic Usage

#### Windows
```powershell
# Scan packages from SBOM file
python sbom_scanner.py --sbom sample_sbom.json

# Scan and show results immediately  
python sbom_scanner.py --sbom sample_sbom.json --show-results

# Skip Docker build if image already exists
python sbom_scanner.py --sbom sample_sbom.json --no-build --show-results
```

#### Linux
```bash
# Scan packages from SBOM file
python3 sbom_scanner.py --sbom sample_sbom.json

# Or run directly (if made executable)
./sbom_scanner.py --sbom sample_sbom.json

# Scan and show results immediately
python3 sbom_scanner.py --sbom sample_sbom.json --show-results

# Skip Docker build if image already exists
python3 sbom_scanner.py --sbom sample_sbom.json --no-build --show-results
```

### Supported SBOM Formats

The scanner supports multiple SBOM formats:

- **Custom JSON**: Simple array of packages (see `sample_sbom.json`)
- **CycloneDX JSON**: Standard CycloneDX format (see `sample_sbom_cyclonedx.json`)
- **SPDX JSON**: Standard SPDX format

**Supported ecosystems:**
- `pypi` or `python` - Python packages from PyPI
- `npm`, `node`, or `javascript` - Node.js packages from npm

### View Results

#### Windows
```powershell
# Export detailed findings to JSON file
python export_findings.py --output security_report.json

# Export findings for specific package
python export_findings.py --package requests --output requests_analysis.json

# View findings in terminal
python export_findings.py

# Quick database query
python -c "import sqlite3; [print(f'{r[0]} {r[1]}=={r[2]} -> {r[3]}') for r in sqlite3.connect('scans.db').execute('SELECT ecosystem,name,version,status FROM scans')]"
```

#### Linux
```bash
# Export detailed findings to JSON file
python3 export_findings.py --output security_report.json

# Export findings for specific package
python3 export_findings.py --package requests --output requests_analysis.json

# View findings in terminal
python3 export_findings.py

# Quick database query
python3 -c "import sqlite3; [print(f'{r[0]} {r[1]}=={r[2]} -> {r[3]}') for r in sqlite3.connect('scans.db').execute('SELECT ecosystem,name,version,status FROM scans')]"
```

### Web-Based Findings Viewer

For a more visual analysis experience, use the included web viewer:

#### Windows:
```powershell
# Export findings for web viewing
python export_findings.py --output findings.json

# Open the web viewer
start viewer\index.html
```

#### Linux:
```bash
# Export findings for web viewing  
python3 export_findings.py --output findings.json

# Open the web viewer
xdg-open viewer/index.html
```

#### Features:
- 🎨 **Interactive Dashboard**: Beautiful, responsive web interface
- 📊 **Visual Statistics**: Package counts, findings overview, status breakdown
- 🔍 **Real-time Search**: Filter packages and findings instantly
- 📱 **Mobile Responsive**: Works on desktop, tablet, and mobile
- 🎯 **Detailed Analysis**: Expandable package cards with finding details
- 🏷️ **Color-coded Status**: Visual indicators for security states

## Creating Your SBOM File

Create a JSON file with your packages to scan. The scanner supports multiple formats:

### Custom Format (Simple)
```json
[
  {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"},
  {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
  {"ecosystem": "pypi", "name": "urllib3", "version": "2.0.4"},
  {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"}
]
```

### CycloneDX Format
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0"
    },
    {
      "type": "library", 
      "name": "left-pad",
      "version": "1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0"
    }
  ]
}
```

**Supported ecosystems:**
- `pypi` or `python` - Python packages from PyPI
- `npm`, `node`, or `javascript` - Node.js packages from npm

## Understanding Results

### Status Types
- **CLEAN**: No suspicious patterns detected
- **FLAGGED**: Potential threats or suspicious patterns found  
- **ERROR**: Failed to install or scan the package

### Finding Categories
- **execution**: Code execution patterns (eval, exec, subprocess)
- **network**: Network communication (HTTP requests, sockets)
- **filesystem**: File system access (read, write, delete operations)
- **crypto**: Cryptographic operations (encryption, base64 encoding)
- **environment**: Environment variable access
- **entropy**: High entropy content suggesting obfuscation
- **base64**: Large base64 payloads (potential malicious content)
- **obfuscation**: Code obfuscation patterns
- **dynamic_import**: Dynamic module loading
- **executable**: Binary executable content
- **yara**: YARA rule matches

### Sample Output
```
pypi requests==2.31.0 -> FLAGGED
  Findings: 400 total
    execution: 2
    network: 54
    filesystem: 3
    environment: 2
    obfuscation: 9
    yara: 330
  Sample findings with content:
    [execution] execution keyword: eval
      Content: ared_request, proxies):\n        """This method re-evaluates the proxy configuration...
      File: requests/sessions.py
```

## Advanced Usage

### Command Line Options

**Main Scanner:**

*Windows:*
```powershell
python sbom_scanner.py [options]
```

*Linux/macOS:*
```bash
python3 sbom_scanner.py [options]
# or
./sbom_scanner.py [options]  # if made executable
```

**Available Options:**
```
  --sbom FILE          Path to SBOM JSON file (required)
  --db PATH           SQLite database path (default: scans.db)
  --no-build          Skip Docker image build
  --image NAME        Custom Docker image name
  --show-results      Display results after scanning
  --help-sbom         Show detailed SBOM format help
  --version           Show version information
  -h, --help          Show help message
```

**Export Tool:**

*Windows:*
```powershell
python export_findings.py [options]
```

*Linux/macOS:*
```bash
python3 export_findings.py [options]
```

**Export Options:**
```
  --output FILE       Output JSON file (default: stdout)
  --package NAME      Filter by package name
  --db PATH          Database path (default: scans.db)
```

### Customizing Detection Rules

Edit `scanner/rules.yar` to add custom YARA rules:

```yara
rule CustomMaliciousPattern
{
    strings:
        $suspicious = "eval(atob("
        $crypto = "crypto.subtle"
    condition:
        any of them
}
```

Then rebuild the Docker image:
```powershell
docker build -t sbom_scanner_image:latest .\scanner
```

### Database Schema

The SQLite database stores results in the `scans` table:
- `ecosystem` - Package ecosystem (pypi/npm)
- `name` - Package name  
- `version` - Package version
- `status` - Scan result (clean/flagged/error)
- `result_json` - Complete findings with content
- `scanned_at` - Timestamp of scan

### Batch Processing

For large SBOM files, the scanner automatically:
- ✅ Skips already-scanned package versions
- ✅ Processes packages sequentially for stability  
- ✅ Stores all results for later analysis
- ✅ Continues on individual package failures

## Troubleshooting

### Common Issues

#### Windows

**Docker build fails:**
```powershell
# Ensure Docker Desktop is running
docker --version

# Check Docker daemon status
docker info
```

**Python not found:**
```powershell
# Use 'py' instead of 'python' on Windows
py sbom_scanner.py --sbom sample_sbom.json

# Or check Python installation
python --version
```

**Permission errors:**
```powershell
# Run PowerShell as Administrator for Docker operations
# Or check Docker Desktop permissions
```

#### Linux

**Docker build fails:**
```bash
# Check if Docker is running
sudo systemctl status docker

# Start Docker if not running
sudo systemctl start docker

# Check Docker version
docker --version
```

**Permission denied (Docker):**
```bash
# Add user to docker group
sudo usermod -a -G docker $USER

# Apply group changes (requires logout/login)
newgrp docker

# Or run with sudo (not recommended)
sudo python3 sbom_scanner.py --sbom sample_sbom.json
```

**Python not found:**
```bash
# Install Python 3
sudo apt install python3 python3-pip  # Ubuntu/Debian
sudo dnf install python3 python3-pip  # RHEL/CentOS/Fedora

# Check Python installation
python3 --version
```

**Script not executable:**
```bash
# Make script executable
chmod +x sbom_scanner.py

# Or always use python3 explicitly
python3 sbom_scanner.py --sbom sample_sbom.json
```

**Package installation fails:**
- Check network connectivity for package downloads
- Some packages may have complex dependencies (scanner uses --no-deps)
- Binary packages may fail on the container architecture

### Performance Tips

- Use `--no-build` after first run to skip image rebuilds
- Large packages (>10MB files) are automatically skipped for memory efficiency
- Scanner processes one package at a time to avoid resource conflicts

## Security Considerations

⚠️ **Important Security Notes:**

- **Isolation**: Packages run inside Docker containers for safety
- **Container Security**: Containers use `--rm` for automatic cleanup
- **Untrusted Code**: Scanner executes package installation scripts
- **Network Access**: Containers can access network for package downloads
- **Production Use**: Consider additional hardening (gVisor, network isolation)

**Recommended Production Setup:**
- Run on dedicated, isolated infrastructure
- Use hardened container runtime (gVisor, kata-containers)
- Enable container monitoring and breakout detection
- Regularly update base images and scanner code
- Implement network segmentation for scanner environment

## Project Structure

```
charming_hera/
├── sbom_scanner.py          # Main orchestrator script
├── scanner/
│   ├── scan_package.py      # Container scanner with content extraction  
│   ├── Dockerfile          # Scanner Docker image definition
│   └── rules.yar           # YARA detection rules
├── export_findings.py       # Export detailed findings to JSON
├── viewer/                  # Web-based findings visualizer
│   ├── index.html          # Interactive HTML dashboard
│   └── README.md           # Viewer documentation
├── sample_sbom.json        # Sample SBOM for testing  
├── setup_windows.ps1       # Windows automated setup script
├── setup_linux.sh         # Linux automated setup script
├── test_undefined_versions.json  # Test SBOM with missing versions
├── Gemini_Generated_Image_dt2z5zdt2z5zdt2z.png  # Charming Hera logo
├── requirements.txt        # Python dependencies (optional)
├── README.md              # This documentation
└── scans.db               # SQLite database (created after first run)
```

## Cross-Platform Compatibility

This scanner is **fully cross-platform** and works identically on Windows, Linux, and macOS.

### Platform Requirements

| Platform | Python | Docker | Notes |
|----------|--------|---------|-------|
| **Windows** | `python` or `py` | Docker Desktop | PowerShell/CMD |
| **Linux** | `python3` | docker.io/docker-ce | bash/sh |
| **macOS** | `python3` | Docker Desktop | bash/zsh |

### Key Differences

#### Command Syntax
```bash
# Windows
python sbom_scanner.py --sbom sample_sbom.json
docker build -t scanner .\scanner

# Linux/macOS  
python3 sbom_scanner.py --sbom sample_sbom.json
docker build -t scanner ./scanner
```

#### File Paths
- **Windows**: Uses backslashes `\` in examples, but code handles both
- **Linux/macOS**: Uses forward slashes `/`
- **Scanner**: All internal paths use forward slashes (works everywhere)

#### Docker Setup
- **Windows**: Docker Desktop with GUI
- **Linux**: Docker daemon via systemd, requires group membership
- **macOS**: Docker Desktop with GUI

### Environment Variables
All platforms support the same environment variables:
```bash
export SBOM_SCANNER_DB="/path/to/custom.db"
export SBOM_SCANNER_IMAGE="my-scanner:v1.0"
```

## Technical Details

### Detection Engine
- **40+ Detection Patterns**: Comprehensive coverage of supply chain attack vectors
- **Context Extraction**: 50-character windows around each detection
- **Binary Analysis**: Hex dumps and entropy analysis for non-text content
- **YARA Integration**: Custom rules with string matching and content preview

### Container Security
- **Isolated Execution**: Each package scanned in fresh container
- **Automatic Cleanup**: `--rm` flag ensures no container accumulation
- **Resource Limits**: 10MB file size limits prevent memory exhaustion
- **Read-only Filesystem**: Container security best practices (optional)

### Database Design
- **SQLite Storage**: Lightweight, portable database
- **Deduplication**: Automatic skipping of previously scanned versions
- **JSON Storage**: Complete findings with content stored as JSON
- **Audit Trail**: Timestamps and scan history for compliance

## Example Workflows

### Security Team Workflow
```powershell
# 1. Scan development dependencies
python sbom_scanner.py --sbom dev_dependencies.sbom --show-results

# 2. Export flagged packages for review
python export_findings.py --output security_review.json

# 3. Generate executive summary
python -c "import sqlite3,json; results=sqlite3.connect('scans.db').execute('SELECT status,COUNT(*) FROM scans GROUP BY status').fetchall(); print('Summary:', dict(results))"
```

### DevOps Integration
```powershell
# CI/CD pipeline integration
python sbom_scanner.py --sbom production.sbom
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Supply chain scan completed"
    python export_findings.py --output artifacts/security_scan.json
} else {
    Write-Host "❌ Supply chain scan failed"
    exit 1
}
```

### Threat Research Workflow  
```powershell
# 1. Scan suspicious packages
python sbom_scanner.py --sbom suspicious_packages.sbom --show-results

# 2. Export detailed analysis with content
python export_findings.py --package malicious-pkg --output forensic_analysis.json

# 3. Extract IOCs for threat intelligence
python -c "import sqlite3,json; [print(f'IOC: {json.loads(r[0])}') for r in sqlite3.connect('scans.db').execute('SELECT result_json FROM scans WHERE status=\"flagged\"').fetchall()]"
```

## Contributing

To extend the scanner's capabilities:

1. **Add Detection Rules**: Edit `scanner/rules.yar` with new YARA rules
2. **Enhance Patterns**: Modify keyword lists in `scanner/scan_package.py`
3. **New Ecosystems**: Add support for Go, Rust, etc. in the install_package function
4. **Output Formats**: Extend `export_findings.py` for CSV, XML, SARIF formats

## License & Disclaimer

This tool is for security research and defensive purposes. Users are responsible for:
- Compliance with applicable laws and regulations
- Proper handling of potentially malicious packages  
- Implementing appropriate security controls in production environments
- Regular updates and maintenance of detection rules

The scanner provides indicators and context but requires human analysis for final threat determination.

