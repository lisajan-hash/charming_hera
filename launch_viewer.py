#!/usr/bin/env python3
"""
Launch the Charming Hera web viewer with a sample JSON file.
This script generates sample data if none exists and opens the viewer.
"""

import json
import os
import sys
import webbrowser
from pathlib import Path

def create_sample_json():
    """Create a sample JSON file for testing the viewer"""
    sample_data = {
        "export_info": {
            "total_packages": 2,
            "export_timestamp": "2025-10-19T12:00:00.000000",
            "total_findings": 5
        },
        "packages": [
            {
                "ecosystem": "pypi",
                "name": "sample-package",
                "version": "1.0.0",
                "status": "flagged",
                "scanned_at": "2025-10-19T12:00:00.000000",
                "total_findings": 3,
                "findings_by_type": {
                    "network": 2,
                    "execution": 1
                },
                "detailed_findings": [
                    {
                        "type": "network",
                        "detail": "network activity: https://",
                        "content": "const url = 'https://api.example.com/data';\\nfetch(url);",
                        "path": "src/network.py"
                    },
                    {
                        "type": "network", 
                        "detail": "network activity: http://",
                        "content": "requests.get('http://insecure-api.com')",
                        "path": "src/requests.py"
                    },
                    {
                        "type": "execution",
                        "detail": "execution keyword: eval",
                        "content": "result = eval(user_input)  # Dangerous!",
                        "path": "src/eval.py"
                    }
                ]
            },
            {
                "ecosystem": "npm",
                "name": "clean-package", 
                "version": "2.1.0",
                "status": "clean",
                "scanned_at": "2025-10-19T12:00:00.000000",
                "total_findings": 0,
                "findings_by_type": {},
                "detailed_findings": []
            }
        ]
    }
    
    sample_path = Path("viewer_sample.json")
    with open(sample_path, 'w') as f:
        json.dump(sample_data, f, indent=2)
    
    print(f"✅ Created sample JSON file: {sample_path}")
    return sample_path

def launch_viewer():
    """Launch the web viewer in default browser"""
    viewer_path = Path("viewer/index.html")
    
    if not viewer_path.exists():
        print("❌ Viewer not found. Make sure you're in the project root directory.")
        return False
    
    # Convert to absolute path and file URL
    abs_path = viewer_path.resolve()
    file_url = f"file:///{abs_path.as_posix()}"
    
    print(f"🌐 Opening viewer in browser: {file_url}")
    
    try:
        webbrowser.open(file_url)
        return True
    except Exception as e:
        print(f"❌ Could not open browser: {e}")
        print(f"   Please manually open: {abs_path}")
        return False

def main():
    print("🔍 Charming Hera - Viewer Launcher")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not Path("sbom_scanner.py").exists():
        print("❌ Please run this script from the Charming Hera project root directory")
        return 1
    
    # Create sample data if needed
    if not Path("viewer_test.json").exists():
        print("📄 No test JSON found, creating sample data...")
        create_sample_json()
    else:
        print("📄 Using existing viewer_test.json")
    
    # Launch viewer
    if launch_viewer():
        print("\n🎉 Viewer launched successfully!")
        print("\n📝 Instructions:")
        print("   1. Click 'Select JSON File' in the viewer")
        print("   2. Choose 'viewer_test.json' or 'viewer_sample.json'")
        print("   3. Explore your SBOM findings!")
        print("\n💡 To export real data: python export_findings.py --output my_findings.json")
    else:
        print("\n❌ Could not launch viewer automatically")
        print("   Please open viewer/index.html manually in your browser")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())