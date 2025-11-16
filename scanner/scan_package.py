#!/usr/bin/env python3
"""
Containerized scanner: installs a single package then scans installed files for indicators.

Outputs a single JSON object to stdout with structure:
{
  "status": "clean"|"flagged"|"error",
  "ecosystem": "npm"|"pypi",
  "name": "package-name",
  "version": "x.y.z",
  "findings": [ {"type":"keyword|base64|yara","path":"/...","detail":"..."}, ... ]
}

This script runs inside Docker and must be run as root (image uses lightweight python base).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import math
from collections import Counter
from pathlib import Path

ROOT_SCAN_DIR = Path("/scan")
YARA_RULES = Path("/scanner/rules.yar")

# Enhanced keyword lists organized by category
EXECUTION_KEYWORDS = ["exec", "execute", "eval", "subprocess", "popen", "os.system", "shell=True", "Function(", "setTimeout", "setInterval"]
NETWORK_KEYWORDS = ["socket.socket", "urllib.request", "requests.", "fetch(", "XMLHttpRequest", "axios", "http://", "https://"]
FILESYSTEM_KEYWORDS = ["fs.readFile", "fs.writeFile", "open(", "chmod(", "unlink(", "os.remove", "os.rmdir", "os.mkdir"]
CRYPTO_KEYWORDS = ["crypto.", "base64.", "btoa(", "atob(", "encrypt(", "decrypt(", "hash("]
ENV_KEYWORDS = ["process.env", "os.environ", "getenv(", "setenv(", "process.cwd", "os.getcwd", "__dirname"]

ALL_KEYWORDS = EXECUTION_KEYWORDS + NETWORK_KEYWORDS + FILESYSTEM_KEYWORDS + CRYPTO_KEYWORDS + ENV_KEYWORDS

# Enhanced regex patterns
BASE64_RE = re.compile(r"(?:(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)")
HEX_PATTERN = re.compile(r"\\x[0-9a-fA-F]{2}")
UNICODE_PATTERN = re.compile(r"\\u[0-9a-fA-F]{4}")
OBFUSCATED_PATTERN = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*\[[\'\"]\w+[\'\"]\]')
DYNAMIC_REQUIRE = re.compile(r'require\s*\(\s*[a-zA-Z_]')
EVAL_PATTERN = re.compile(r'(eval|exec)\s*\(')


def calculate_entropy(data):
    """Calculate Shannon entropy of data to detect obfuscated content"""
    if not data:
        return 0
    
    # Count frequency of each byte
    counts = Counter(data)
    total = len(data)
    
    # Calculate entropy
    entropy = 0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def run_cmd(cmd, cwd=None, capture_output=False):
    return subprocess.run(cmd, shell=False, cwd=cwd, capture_output=capture_output, text=True)


def install_package(ecosystem, name, version):
    # create a fresh venv or node_modules under /scan
    if ROOT_SCAN_DIR.exists():
        shutil.rmtree(ROOT_SCAN_DIR)
    ROOT_SCAN_DIR.mkdir(parents=True, exist_ok=True)

    if ecosystem.lower() in ("pypi", "python"):
        # use pip to install into /scan
        # Handle undefined/null versions by installing latest
        if version and version.strip() and version.lower() not in ("null", "none", "undefined"):
            pkg = f"{name}=={version}"
        else:
            pkg = name  # Install latest version
            print(f"Warning: No version specified for {name}, installing latest version", file=sys.stderr)
        cmd = [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(ROOT_SCAN_DIR), pkg]
        r = run_cmd(cmd, capture_output=True)
        # Return the actual package installation path for PyPI
        package_path = ROOT_SCAN_DIR / name.replace("-", "_")  # pip normalizes package names
        if not package_path.exists():
            # Try original name if normalized doesn't exist
            package_path = ROOT_SCAN_DIR / name
        return r.returncode == 0, r.stdout + r.stderr, package_path

    elif ecosystem.lower() in ("npm", "node", "javascript"):
        # initialize package.json then npm install into /scan
        Path("/tmp").mkdir(exist_ok=True)
        cmd_init = ["npm", "init", "-y"]
        r_init = run_cmd(cmd_init, cwd=str(ROOT_SCAN_DIR), capture_output=True)
        
        # Handle undefined/null versions by installing latest
        if version and version.strip() and version.lower() not in ("null", "none", "undefined"):
            package_spec = f"{name}@{version}"
        else:
            package_spec = name  # Install latest version
            print(f"Warning: No version specified for {name}, installing latest version", file=sys.stderr)
        
        cmd_install = ["npm", "install", package_spec, "--no-audit", "--no-fund"]
        r = run_cmd(cmd_install, cwd=str(ROOT_SCAN_DIR), capture_output=True)
        # Return the actual package installation path for npm
        package_path = ROOT_SCAN_DIR / "node_modules" / name
        return r.returncode == 0, r.stdout + r.stderr, package_path

    else:
        return False, f"unsupported ecosystem: {ecosystem}", None


def extract_context(text, pattern, max_length=200):
    """Extract context around a found pattern"""
    if isinstance(pattern, str):
        # Simple string search
        pos = text.find(pattern)
        if pos == -1:
            return None
        start = max(0, pos - 50)
        end = min(len(text), pos + len(pattern) + 50)
        context = text[start:end].replace('\n', '\\n').replace('\r', '\\r')
        return context[:max_length]
    else:
        # For regex match objects, extract the position info
        if hasattr(pattern, 'start') and hasattr(pattern, 'end'):
            # It's already a match object
            start = max(0, pattern.start() - 50)
            end = min(len(text), pattern.end() + 50)
            context = text[start:end].replace('\n', '\\n').replace('\r', '\\r')
            return context[:max_length]
        else:
            # It's a regex pattern, need to search
            match = pattern.search(text)
            if not match:
                return None
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end].replace('\n', '\\n').replace('\r', '\\r')
            return context[:max_length]


def scan_files(package_path):
    """Scan only the specific package installation directory"""
    findings = []
    
    if not package_path or not package_path.exists():
        print(f"Warning: Package path {package_path} does not exist", file=sys.stderr)
        return findings
    
    print(f"Scanning package directory: {package_path}", file=sys.stderr)
    
    # walk files only under the specific package directory
    for root, dirs, files in os.walk(str(package_path)):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
            except Exception:
                continue

            # Skip very large files to avoid memory issues
            if len(data) > 10 * 1024 * 1024:  # 10MB limit
                continue

            # Calculate entropy for obfuscation detection
            entropy = calculate_entropy(data)
            if entropy > 7.0:  # High entropy suggests obfuscation
                # For binary data, show first 100 bytes as hex
                content_preview = data[:100].hex() if len(data) > 0 else ""
                findings.append({
                    "type": "entropy", 
                    "path": fpath, 
                    "detail": f"high entropy ({entropy:.2f}) - possible obfuscation",
                    "content": content_preview,
                    "file_size": len(data)
                })

            # Decode text for pattern matching
            text = None
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                text = None

            if text:
                # Enhanced keyword detection with categories and content extraction
                for kw in EXECUTION_KEYWORDS:
                    if kw in text:
                        context = extract_context(text, kw)
                        findings.append({
                            "type": "execution", 
                            "path": fpath, 
                            "detail": f"execution keyword: {kw}",
                            "content": context,
                            "keyword": kw
                        })

                for kw in NETWORK_KEYWORDS:
                    if kw in text:
                        context = extract_context(text, kw)
                        findings.append({
                            "type": "network", 
                            "path": fpath, 
                            "detail": f"network activity: {kw}",
                            "content": context,
                            "keyword": kw
                        })

                for kw in FILESYSTEM_KEYWORDS:
                    if kw in text:
                        context = extract_context(text, kw)
                        findings.append({
                            "type": "filesystem", 
                            "path": fpath, 
                            "detail": f"filesystem access: {kw}",
                            "content": context,
                            "keyword": kw
                        })

                for kw in CRYPTO_KEYWORDS:
                    if kw in text:
                        context = extract_context(text, kw)
                        findings.append({
                            "type": "crypto", 
                            "path": fpath, 
                            "detail": f"crypto operation: {kw}",
                            "content": context,
                            "keyword": kw
                        })

                for kw in ENV_KEYWORDS:
                    if kw in text:
                        context = extract_context(text, kw)
                        findings.append({
                            "type": "environment", 
                            "path": fpath, 
                            "detail": f"environment access: {kw}",
                            "content": context,
                            "keyword": kw
                        })

                # Enhanced pattern detection with content
                for m in BASE64_RE.finditer(text):
                    s = m.group(0)
                    if len(s) > 100:  # Likely payload
                        context = extract_context(text, s)
                        findings.append({
                            "type": "base64", 
                            "path": fpath, 
                            "detail": f"large base64 string ({len(s)} chars): {s[:50]}...",
                            "content": context,
                            "base64_length": len(s)
                        })

                # Hex pattern detection
                hex_matches = HEX_PATTERN.findall(text)
                if len(hex_matches) > 10:  # Multiple hex escapes
                    # Find the first occurrence for context
                    first_match = HEX_PATTERN.search(text)
                    context = extract_context(text, first_match) if first_match else None
                    findings.append({
                        "type": "hex_escape", 
                        "path": fpath, 
                        "detail": f"multiple hex escapes ({len(hex_matches)} found)",
                        "content": context,
                        "hex_count": len(hex_matches)
                    })

                # Unicode pattern detection
                unicode_matches = UNICODE_PATTERN.findall(text)
                if len(unicode_matches) > 5:  # Multiple unicode escapes
                    first_match = UNICODE_PATTERN.search(text)
                    context = extract_context(text, first_match) if first_match else None
                    findings.append({
                        "type": "unicode_escape", 
                        "path": fpath, 
                        "detail": f"multiple unicode escapes ({len(unicode_matches)} found)",
                        "content": context,
                        "unicode_count": len(unicode_matches)
                    })

                # Obfuscated property access
                obf_match = OBFUSCATED_PATTERN.search(text)
                if obf_match:
                    context = extract_context(text, obf_match)
                    findings.append({
                        "type": "obfuscation", 
                        "path": fpath, 
                        "detail": "obfuscated property access pattern",
                        "content": context,
                        "pattern": obf_match.group(0)
                    })

                # Dynamic require/import
                dyn_match = DYNAMIC_REQUIRE.search(text)
                if dyn_match:
                    context = extract_context(text, dyn_match)
                    findings.append({
                        "type": "dynamic_import", 
                        "path": fpath, 
                        "detail": "dynamic require/import pattern",
                        "content": context,
                        "pattern": dyn_match.group(0)
                    })

                # Eval patterns
                eval_match = EVAL_PATTERN.search(text)
                if eval_match:
                    context = extract_context(text, eval_match)
                    findings.append({
                        "type": "eval_pattern", 
                        "path": fpath, 
                        "detail": "eval/exec function call pattern",
                        "content": context,
                        "pattern": eval_match.group(0)
                    })

            # Binary file analysis for executable content
            if not text and len(data) > 0:
                # Check for executable headers
                if data.startswith(b'\x7fELF') or data.startswith(b'MZ'):
                    header_hex = data[:32].hex()  # First 32 bytes as hex
                    findings.append({
                        "type": "executable", 
                        "path": fpath, 
                        "detail": "contains executable binary",
                        "content": header_hex,
                        "file_size": len(data)
                    })

    # run yara if available - scan only the package directory
    try:
        if shutil.which("yara") and YARA_RULES.exists():
            cmd = ["yara", "-r", "-s", str(YARA_RULES), str(package_path)]  # -s flag shows matched strings
            r = run_cmd(cmd, capture_output=True)
            out = r.stdout or r.stderr
            for line in (out or "").splitlines():
                if line.strip() and not line.startswith("warning"):
                    # Parse yara output: rule_name file_path
                    parts = line.strip().split(' ', 1)
                    if len(parts) >= 2:
                        rule_name = parts[0]
                        file_path = parts[1] if len(parts) > 1 else ""
                        
                        # Try to read the file for context
                        content_preview = ""
                        try:
                            if os.path.exists(file_path):
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    file_content = f.read()
                                    # Show first 300 chars of the file
                                    content_preview = file_content[:300].replace('\n', '\\n')
                        except Exception:
                            content_preview = "Unable to read file content"
                        
                        findings.append({
                            "type": "yara", 
                            "path": file_path, 
                            "detail": f"yara rule match: {rule_name}",
                            "content": content_preview,
                            "rule": rule_name
                        })
    except Exception as e:
        # Don't fail the scan if yara has issues
        pass

    return findings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ecosystem", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--version", required=True)
    args = p.parse_args()

    result = {
        "ecosystem": args.ecosystem,
        "name": args.name,
        "version": args.version,
        "status": "error",
        "findings": [],
    }

    ok, out, package_path = install_package(args.ecosystem, args.name, args.version)
    if not ok:
        result["status"] = "error"
        result["error"] = out
        print(json.dumps(result))
        return 1

    findings = scan_files(package_path)
    result["findings"] = findings
    result["status"] = "flagged" if findings else "clean"
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
