#!/usr/bin/env python3
"""
Orchestrator for SBOM scanning.

Usage: python sbom_scanner.py --sbom sample_sbom.json

"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @staticmethod
    def is_windows():
        return os.name == 'nt'
    
    @staticmethod
    def enable_windows_colors():
        """Enable ANSI colors on Windows 10+"""
        if Colors.is_windows():
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except:
                return False
        return True

def colored_print(text, color=Colors.WHITE, bold=False, end='\n'):
    """Print colored text with optional bold formatting"""
    if not Colors.enable_windows_colors():
        # Fallback for systems that don't support ANSI colors
        print(text, end=end)
        return
    
    style = Colors.BOLD if bold else ''
    print(f"{style}{color}{text}{Colors.RESET}", end=end)

DB_PATH = os.environ.get("SBOM_SCANNER_DB", "scans.db")
IMAGE_NAME = os.environ.get("SBOM_SCANNER_IMAGE", "sbom_scanner_image:latest")


def parse_sbom(sbom_data):
    """
    Parse SBOM data supporting multiple formats:
    - Custom format: [{"ecosystem": "pypi", "name": "pkg", "version": "1.0"}]
    - CycloneDX: {"bomFormat": "CycloneDX", "components": [...]}
    - SPDX: {"spdxVersion": "SPDX-2.3", "packages": [...]}
    """
    if isinstance(sbom_data, list):
        # Custom format
        return sbom_data
    elif isinstance(sbom_data, dict):
        if sbom_data.get("bomFormat") == "CycloneDX":
            components = sbom_data.get("components", [])
            parsed = []
            for comp in components:
                name = comp.get("name")
                version = comp.get("version")
                purl = comp.get("purl", "")
                ecosystem = None
                if purl.startswith("pkg:pypi/"):
                    ecosystem = "pypi"
                elif purl.startswith("pkg:npm/"):
                    ecosystem = "npm"
                elif purl.startswith("pkg:deb/"):
                    ecosystem = "deb"  # If supported
                # Add more ecosystems as needed
                if ecosystem and name:
                    if not version:
                        version = "latest"
                    parsed.append({"ecosystem": ecosystem, "name": name, "version": version})
            return parsed
        elif "spdxVersion" in sbom_data:
            # SPDX format
            packages = sbom_data.get("packages", [])
            parsed = []
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("versionInfo")
                # Determine ecosystem from externalRefs or name patterns
                ecosystem = None
                external_refs = pkg.get("externalRefs", [])
                for ref in external_refs:
                    if ref.get("referenceType") == "purl":
                        purl = ref.get("referenceLocator", "")
                        if purl.startswith("pkg:pypi/"):
                            ecosystem = "pypi"
                        elif purl.startswith("pkg:npm/"):
                            ecosystem = "npm"
                        break
                if not ecosystem:
                    # Fallback: guess from name
                    if name and ("-" in name or "." in name):  # Rough heuristic
                        ecosystem = "pypi"  # Default to pypi
                if ecosystem and name:
                    if not version:
                        version = "latest"
                    parsed.append({"ecosystem": ecosystem, "name": name, "version": version})
            return parsed
    return []


def ensure_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            ecosystem TEXT,
            name TEXT,
            version TEXT,
            status TEXT,
            result_json TEXT,
            scanned_at TEXT,
            UNIQUE(ecosystem,name,version)
        )
        """
    )
    conn.commit()
    return conn


def already_scanned(conn, ecosystem, name, version):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, status, scanned_at FROM scans WHERE ecosystem=? AND name=? AND version=?",
        (ecosystem, name, version),
    )
    row = cur.fetchone()
    return row


def save_result(conn, ecosystem, name, version, status, result_json):
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO scans (ecosystem,name,version,status,result_json,scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
        (ecosystem, name, version, status, json.dumps(result_json), datetime.utcnow().isoformat()),
    )
    conn.commit()


def build_image(image_name=IMAGE_NAME):
    colored_print(f"🏗️  Building scanner image '{image_name}' (this may take a while)...", Colors.CYAN, bold=True)
    try:
        proc = subprocess.run(
            ["docker", "build", "-t", image_name, "scanner"], 
            capture_output=True, 
            text=True,
            encoding='utf-8',
            errors='replace'  # Replace problematic characters instead of failing
        )
    except UnicodeDecodeError:
        # Fallback to bytes mode if encoding fails
        proc = subprocess.run(["docker", "build", "-t", image_name, "scanner"], capture_output=True)
        # Convert bytes to string, replacing problematic characters
        proc.stdout = proc.stdout.decode('utf-8', errors='replace') if proc.stdout else ""
        proc.stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ""
    
    if proc.returncode != 0:
        colored_print("❌ Docker build failed:", Colors.RED, bold=True)
        print(proc.stdout, proc.stderr)
        raise SystemExit(1)
    colored_print("✅ Docker image built successfully", Colors.GREEN, bold=True)


def run_scan_in_container(image_name, ecosystem, name, version, timeout=300):
    cmd = [
        "docker",
        "run",
        "--rm",
        image_name,
        "--ecosystem",
        ecosystem,
        "--name",
        name,
        "--version",
        version,
    ]
    colored_print("🚀 Running container scan...", Colors.BLUE)
    try:
        proc = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            encoding='utf-8',
            errors='replace'
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "stdout": "", "stderr": "scan timed out"}
    except UnicodeDecodeError:
        # Fallback to bytes mode if encoding fails
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
            # Convert bytes to string, replacing problematic characters
            proc.stdout = proc.stdout.decode('utf-8', errors='replace') if proc.stdout else ""
            proc.stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ""
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "stdout": "", "stderr": "scan timed out"}

    return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def mock_scan_package(ecosystem, name, version):
    """Simulate a package scan with fake results for testing purposes"""
    import random
    import time
    
    colored_print("🚀 Running mock scan...", Colors.BLUE)
    time.sleep(0.5)  # Simulate processing time
    
    # Generate fake results based on package name (deterministic for testing)
    random.seed(hash(f"{ecosystem}:{name}:{version}"))
    
    # Some packages are "flagged", some are "clean"
    if random.random() < 0.3:  # 30% chance of being flagged
        status = "flagged"
        findings = []
        num_findings = random.randint(1, 5)
        for i in range(num_findings):
            finding_types = ["security", "vulnerability", "malware", "license", "deprecated"]
            finding_type = random.choice(finding_types)
            findings.append({
                "type": finding_type,
                "detail": f"Mock {finding_type} issue #{i+1}",
                "content": f"Sample content for {finding_type} finding",
                "path": f"/scan/{name}/file_{i+1}.py",
                "line": random.randint(1, 100)
            })
    else:
        status = "clean"
        findings = []
    
    result = {
        "status": status,
        "findings": findings,
        "scan_time": time.time(),
        "package": f"{ecosystem}/{name}=={version}",
        "mock": True
    }
    
    return {"returncode": 0, "stdout": json.dumps(result), "stderr": ""}


def show_results(db_path):
    """Display scan results in a colorized format"""
    conn = sqlite3.connect(db_path)
    results = conn.execute('SELECT ecosystem,name,version,status,result_json FROM scans ORDER BY scanned_at DESC').fetchall()
    
    if not results:
        colored_print("\n📭 No scan results found.", Colors.YELLOW)
        return
    
    colored_print("\n" + "=" * 60, Colors.BLUE, bold=True)
    colored_print("🔍 SCAN RESULTS", Colors.CYAN, bold=True)
    colored_print("=" * 60, Colors.BLUE, bold=True)
    
    for row in results:
        ecosystem, name, version, status, result_json = row
        data = json.loads(result_json)
        findings = data.get("findings", [])
        
        # Status-based coloring
        if status.upper() == "FLAGGED":
            status_color = Colors.RED
            status_icon = "🚨"
        elif status.upper() == "CLEAN":
            status_color = Colors.GREEN
            status_icon = "✅"
        elif status.upper() == "ERROR":
            status_color = Colors.YELLOW
            status_icon = "❌"
        else:
            status_color = Colors.WHITE
            status_icon = "❓"
            
        colored_print(f"\n{status_icon} {ecosystem} {name}=={version}", Colors.CYAN, bold=True, end="")
        colored_print(f" -> {status.upper()}", status_color, bold=True)
        
        if findings:
            colored_print(f"  📊 Findings: {len(findings)} total", Colors.WHITE)
            # Group by type and show counts
            by_type = {}
            for finding in findings:
                ftype = finding.get("type", "unknown")
                by_type[ftype] = by_type.get(ftype, 0) + 1
            
            for ftype, count in sorted(by_type.items()):
                colored_print(f"    📋 {ftype}: {count}", Colors.MAGENTA)
                
            # Show some sample findings with content
            colored_print(f"  🔍 Sample findings with content:", Colors.YELLOW)
            shown = 0
            for finding in findings:
                if shown >= 3:  # Show max 3 samples
                    break
                if finding.get("content"):
                    colored_print(f"    🔸 [{finding.get('type')}] {finding.get('detail')}", Colors.CYAN)
                    print(f"      📝 Content: {finding.get('content')[:150]}...")
                    file_path = finding.get('path', '').replace('/scan/', '')
                    colored_print(f"      📁 File: {file_path}", Colors.BLUE)
                    shown += 1
            if len(findings) > 3:
                colored_print(f"    ⬇️  ... and {len(findings) - 3} more findings", Colors.YELLOW)
        else:
            colored_print("  ✅ No findings", Colors.GREEN)
    
    conn.close()


def print_sbom_help():
    """Print detailed SBOM format help and examples"""
    help_text = """
SBOM (Software Bill of Materials) Format Guide
==============================================

The SBOM file must be a valid JSON array containing package objects.

Required Fields:
  - ecosystem: The package ecosystem (case-insensitive)
  - name: The package name

Optional Fields:
  - version: Package version (if omitted, latest version will be installed)

Supported Ecosystems:
  - "pypi" or "python": Python packages from PyPI
  - "npm", "node", or "javascript": Node.js packages from npm

SBOM Examples:
=============

Basic SBOM with versions:
[
  {
    "ecosystem": "pypi",
    "name": "requests", 
    "version": "2.31.0"
  },
  {
    "ecosystem": "npm",
    "name": "lodash",
    "version": "4.17.21"
  }
]

SBOM with mixed version formats (all supported):
[
  {
    "ecosystem": "pypi",
    "name": "requests"
  },
  {
    "ecosystem": "npm", 
    "name": "lodash",
    "version": null
  },
  {
    "ecosystem": "pypi",
    "name": "urllib3",
    "version": ""
  },
  {
    "ecosystem": "npm",
    "name": "chalk", 
    "version": "undefined"
  }
]

Real-world SBOM example:
[
  {
    "ecosystem": "pypi",
    "name": "django",
    "version": "4.2.7"
  },
  {
    "ecosystem": "pypi", 
    "name": "psycopg2-binary",
    "version": "2.9.7"
  },
  {
    "ecosystem": "npm",
    "name": "react",
    "version": "18.2.0"
  },
  {
    "ecosystem": "npm",
    "name": "express"
  }
]

Version Handling:
================
When version is missing, null, empty, or "undefined":
- The scanner will install the latest available version
- A warning will be displayed during scanning
- The package will be stored in the database with version "latest"

Usage Examples:
==============
# Scan with built-in help
python sbom_scanner.py --help

# Show this detailed SBOM help
python sbom_scanner.py --help-sbom

# Basic scan
python sbom_scanner.py --sbom my_packages.json --show-results

# Fast scan (skip Docker rebuild)
python sbom_scanner.py --sbom my_packages.json --no-build --show-results
    """
    print(help_text)


def main():
    p = argparse.ArgumentParser(
        prog="Charming Hera",
        description="SBOM Security Scanner - Analyzes Software Bill of Materials (SBOM) for security vulnerabilities in npm and Python packages",
        epilog="""
Examples:
  # Basic scan with results display
  python sbom_scanner.py --sbom my_sbom.json --show-results
  
  # Skip Docker image rebuild (faster for repeated scans)
  python sbom_scanner.py --sbom my_sbom.json --no-build --show-results
  
  # Dry run to test SBOM parsing without scanning
  python sbom_scanner.py --sbom my_sbom.json --dry-run
  
  # Mock scan for testing without Docker
  python sbom_scanner.py --sbom my_sbom.json --mock-scan --show-results
  
  # Use custom database and Docker image
  python sbom_scanner.py --sbom my_sbom.json --db custom.db --image my_scanner:v1.0
  
SBOM Format:
  The SBOM file should be a JSON array of objects with these fields:
  - ecosystem: "pypi", "python", "npm", "node", or "javascript"
  - name: package name (required)
  - version: package version (optional - will use latest if missing)
  
  Example SBOM:
  [
    {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"},
    {"ecosystem": "npm", "name": "lodash"},
    {"ecosystem": "pypi", "name": "urllib3", "version": null}
  ]
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    p.add_argument("--sbom", 
                   help="Path to SBOM JSON file containing packages to scan")
    
    # Optional configuration
    p.add_argument("--db", default=DB_PATH, 
                   help=f"SQLite database path for storing results (default: {DB_PATH})")
    p.add_argument("--image", default=IMAGE_NAME, 
                   help=f"Docker image name for the scanner (default: {IMAGE_NAME})")
    
    # Behavior flags
    p.add_argument("--no-build", action="store_true", 
                   help="Skip Docker image build (assumes image already exists)")
    p.add_argument("--dry-run", action="store_true", 
                   help="Parse SBOM and show what would be scanned without running actual scans")
    p.add_argument("--mock-scan", action="store_true", 
                   help="Simulate scanning with fake results (for testing without Docker)")
    p.add_argument("--show-results", action="store_true", 
                   help="Display scan results summary after completion")
    
    # Help and version
    p.add_argument("--help-sbom", action="store_true", 
                   help="Show detailed SBOM format examples and exit")
    p.add_argument("--version", action="version", version="Charming Hera v1.0")
    args = p.parse_args()

    # Handle special help argument
    if args.help_sbom:
        print_sbom_help()
        return

    # Validate required arguments for normal operation
    if not args.sbom:
        colored_print("❌ Error: --sbom argument is required", Colors.RED, bold=True)
        p.print_help()
        raise SystemExit(1)

    if not os.path.exists(args.sbom):
        colored_print(f"❌ SBOM file not found: {args.sbom}", Colors.RED, bold=True)
        raise SystemExit(1)

    with open(args.sbom, "r", encoding="utf-8") as f:
        sbom_raw = json.load(f)

    sbom = parse_sbom(sbom_raw)

    # Handle dry run mode
    if args.dry_run:
        colored_print("🔍 DRY RUN MODE - Parsing SBOM without scanning", Colors.CYAN, bold=True)
        colored_print("=" * 60, Colors.BLUE, bold=True)
        colored_print(f"📄 SBOM File: {args.sbom}", Colors.WHITE)
        colored_print(f"📦 Packages found: {len(sbom)}", Colors.GREEN)
        colored_print("", Colors.WHITE)
        
        for i, item in enumerate(sbom, 1):
            ecosystem = item.get("ecosystem", "unknown")
            name = item.get("name", "unknown")
            version = item.get("version", "latest")
            
            if not version or version.strip() == "" or version.lower() in ("null", "none", "undefined"):
                version = "latest"
            
            colored_print(f"{i:2d}. {ecosystem} {name}=={version}", Colors.CYAN)
        
        colored_print("", Colors.WHITE)
        colored_print("✅ SBOM parsing successful!", Colors.GREEN, bold=True)
        colored_print("💡 To run actual scans, ensure Docker is installed and run without --dry-run", Colors.YELLOW)
        return

    conn = ensure_db(args.db)

    if not args.no_build and not args.mock_scan:
        build_image(args.image)

    summary = {"scanned": 0, "skipped": 0, "errors": 0, "flagged": 0, "clean": 0}

    for item in sbom:
        ecosystem = item.get("ecosystem")
        name = item.get("name")
        version = item.get("version")
        
        # Handle missing or undefined versions
        if not ecosystem or not name:
            colored_print("⚠️  Skipping malformed SBOM item (missing ecosystem or name):", Colors.YELLOW, bold=True)
            print("   ", item)
            continue
        
        # If version is missing or null, use "latest" as a placeholder for DB storage
        if not version or version.strip() == "" or version.lower() in ("null", "none", "undefined"):
            version = "latest"
            colored_print(f"⚠️  Warning: No version specified for {ecosystem}/{name}, will install latest version", Colors.YELLOW)

        colored_print("─" * 60, Colors.BLUE)
        colored_print(f"📦 Processing {ecosystem} {name}=={version}", Colors.CYAN, bold=True)
        if already_scanned(conn, ecosystem, name, version):
            colored_print("⏭️  Already scanned, skipping", Colors.YELLOW)
            summary["skipped"] += 1
            continue

        # Use mock scanning if requested, otherwise use real Docker scanning
        if args.mock_scan:
            res = mock_scan_package(ecosystem, name, version)
        else:
            res = run_scan_in_container(args.image, ecosystem, name, version)

        if res.get("returncode") is None:
            # timeout or other wrapper error
            colored_print("❌ Scan failed:", Colors.RED, bold=True)
            print("   ", res)
            save_result(conn, ecosystem, name, version, "error", res)
            summary["errors"] += 1
            continue

        if res["returncode"] != 0:
            colored_print("❌ Scanner container error:", Colors.RED, bold=True)
            print("   ", res["stderr"])
            try:
                payload = json.loads(res["stdout"]) if res["stdout"] else {"error": res["stderr"]}
            except Exception:
                payload = {"error": res["stderr"], "stdout": res["stdout"]}
            save_result(conn, ecosystem, name, version, "error", payload)
            summary["errors"] += 1
            continue

        try:
            payload = json.loads(res["stdout"]) if res["stdout"] else {"error": "no output"}
        except Exception as e:
            colored_print("⚠️  Failed parsing scanner output:", Colors.YELLOW, bold=True)
            print("   ", e)
            payload = {"error": "invalid-json", "stdout": res["stdout"], "stderr": res["stderr"]}

        status = payload.get("status", "unknown")
        save_result(conn, ecosystem, name, version, status, payload)
        summary["scanned"] += 1
        
        # Show status with color
        if status == "flagged":
            colored_print("🚨 FLAGGED - Security issues detected", Colors.RED, bold=True)
            summary["flagged"] += 1
        elif status == "clean":
            colored_print("✅ CLEAN - No issues found", Colors.GREEN, bold=True)
            summary["clean"] += 1
        else:
            colored_print(f"❓ Status: {status}", Colors.YELLOW)

    colored_print("\n" + "=" * 60, Colors.BLUE, bold=True)
    colored_print("📊 SCAN SUMMARY", Colors.CYAN, bold=True)
    colored_print("=" * 60, Colors.BLUE, bold=True)
    
    # Color-coded summary
    if summary["scanned"] > 0:
        colored_print(f"✅ Scanned:  {summary['scanned']}", Colors.GREEN)
    if summary["skipped"] > 0:
        colored_print(f"⏭️  Skipped:  {summary['skipped']}", Colors.YELLOW) 
    if summary["errors"] > 0:
        colored_print(f"❌ Errors:   {summary['errors']}", Colors.RED)
    if summary["flagged"] > 0:
        colored_print(f"🚨 Flagged:  {summary['flagged']}", Colors.RED, bold=True)
    if summary["clean"] > 0:
        colored_print(f"🔒 Clean:    {summary['clean']}", Colors.GREEN)
    
    # Show results if requested
    if args.show_results:
        show_results(args.db)


if __name__ == "__main__":
    main()
