#!/usr/bin/env python3
"""
Export detailed SBOM scan results to JSON file for analysis.

Usage: python export_findings.py [--output findings.json] [--package package_name]
"""

import argparse
import sqlite3
import json
import sys
import os

# Simple color support
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def colored_print(text, color=Colors.RESET, bold=False):
    """Print colored text"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass
    
    style = Colors.BOLD if bold else ''
    print(f"{style}{color}{text}{Colors.RESET}")

def export_findings(db_path="scans.db", output_file=None, package_filter=None):
    """Export detailed findings to JSON file"""
    
    try:
        conn = sqlite3.connect(db_path)
        if package_filter:
            results = conn.execute(
                'SELECT ecosystem,name,version,status,result_json,scanned_at FROM scans WHERE name LIKE ? ORDER BY scanned_at DESC',
                (f'%{package_filter}%',)
            ).fetchall()
        else:
            results = conn.execute(
                'SELECT ecosystem,name,version,status,result_json,scanned_at FROM scans ORDER BY scanned_at DESC'
            ).fetchall()
        
        if not results:
            print("No scan results found.")
            return
        
        exported_data = {
            "export_info": {
                "total_packages": len(results),
                "export_timestamp": None
            },
            "packages": []
        }
        
        total_findings = 0
        
        for row in results:
            ecosystem, name, version, status, result_json, scanned_at = row
            data = json.loads(result_json)
            findings = data.get("findings", [])
            total_findings += len(findings)
            
            package_data = {
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "status": status,
                "scanned_at": scanned_at,
                "total_findings": len(findings),
                "findings_by_type": {},
                "detailed_findings": findings
            }
            
            # Group findings by type for summary
            for finding in findings:
                ftype = finding.get("type", "unknown")
                if ftype not in package_data["findings_by_type"]:
                    package_data["findings_by_type"][ftype] = 0
                package_data["findings_by_type"][ftype] += 1
            
            exported_data["packages"].append(package_data)
        
        exported_data["export_info"]["total_findings"] = total_findings
        
        # Write to file or stdout
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(exported_data, f, indent=2, ensure_ascii=False)
            colored_print(f"✅ Exported {len(results)} packages with {total_findings} total findings to {output_file}", Colors.GREEN, bold=True)
        else:
            print(json.dumps(exported_data, indent=2, ensure_ascii=False))
        
        conn.close()
        
    except Exception as e:
        colored_print(f"❌ Error exporting findings: {e}", Colors.RED, bold=True)
        return 1

def main():
    parser = argparse.ArgumentParser(description="Export SBOM scan findings to JSON")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--package", "-p", help="Filter by package name (partial match)")
    parser.add_argument("--db", default="scans.db", help="Database path")
    
    args = parser.parse_args()
    
    return export_findings(args.db, args.output, args.package)

if __name__ == "__main__":
    sys.exit(main() or 0)