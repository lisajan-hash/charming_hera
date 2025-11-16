# Charming Hera Setup Script for Windows
# Run this in PowerShell as Administrator

Write-Host "🔍 Charming Hera Setup for Windows" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠️  This script should be run as Administrator for Docker Desktop installation" -ForegroundColor Yellow
    Write-Host "   Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host "   Or install Docker Desktop manually and run this script normally" -ForegroundColor Yellow
}

# Check Python
Write-Host "🐍 Checking Python..." -ForegroundColor Green
try {
    $pythonVersion = python --version 2>$null
    if ($pythonVersion) {
        Write-Host "✅ $pythonVersion found" -ForegroundColor Green
    } else {
        $pyVersion = py --version 2>$null
        if ($pyVersion) {
            Write-Host "✅ $pyVersion found (use 'py' command)" -ForegroundColor Green
        } else {
            throw "Python not found"
        }
    }
} catch {
    Write-Host "❌ Python not found. Please install Python 3.7+ from:" -ForegroundColor Red
    Write-Host "   https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check Docker Desktop
Write-Host "🐳 Checking Docker Desktop..." -ForegroundColor Green
try {
    $dockerVersion = docker --version 2>$null
    if ($dockerVersion) {
        Write-Host "✅ $dockerVersion found" -ForegroundColor Green
        
        # Check if Docker is running
        try {
            docker info >$null 2>&1
            Write-Host "✅ Docker is running" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Docker Desktop is installed but not running" -ForegroundColor Yellow
            Write-Host "   Please start Docker Desktop" -ForegroundColor Yellow
        }
    } else {
        throw "Docker not found"
    }
} catch {
    Write-Host "❌ Docker Desktop not found. Please install from:" -ForegroundColor Red
    Write-Host "   https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    
    if ($isAdmin) {
        Write-Host "📥 Attempting to install Docker Desktop via winget..." -ForegroundColor Yellow
        try {
            winget install Docker.DockerDesktop
            Write-Host "✅ Docker Desktop installed. Please restart this script." -ForegroundColor Green
        } catch {
            Write-Host "❌ Automatic installation failed. Please install manually." -ForegroundColor Red
        }
    }
    exit 1
}

# Build Docker image
Write-Host "🏗️  Building scanner Docker image..." -ForegroundColor Green
if (Test-Path "scanner") {
    try {
        docker build -t sbom_scanner_image:latest .\scanner
        Write-Host "✅ Docker image built successfully" -ForegroundColor Green
    } catch {
        Write-Host "❌ Docker build failed. Check Docker Desktop is running." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "❌ Scanner directory not found. Make sure you're in the project root." -ForegroundColor Red
    exit 1
}

# Test the setup
Write-Host "🧪 Testing setup..." -ForegroundColor Green
try {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        python sbom_scanner.py --help >$null
        Write-Host "✅ Scanner is working (use 'python' command)" -ForegroundColor Green
        $pythonCmd = "python"
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        py sbom_scanner.py --help >$null
        Write-Host "✅ Scanner is working (use 'py' command)" -ForegroundColor Green
        $pythonCmd = "py"
    } else {
        throw "Scanner test failed"
    }
} catch {
    Write-Host "❌ Scanner test failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🎉 Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Test: $pythonCmd sbom_scanner.py --help"
Write-Host "   2. Run: $pythonCmd sbom_scanner.py --sbom sample_sbom.json --show-results"
Write-Host ""
Write-Host "💡 Tip: Use --no-build flag for faster subsequent runs" -ForegroundColor Yellow