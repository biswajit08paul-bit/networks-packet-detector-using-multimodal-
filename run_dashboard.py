"""
Main Launcher for Real IDS System
Run this file to start everything
"""

import os
import sys
import subprocess

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_header():
    print("\n" + "="*60)
    print("     REAL INTRUSION DETECTION SYSTEM")
    print("     Monitoring Your Live Network")
    print("="*60 + "\n")

def check_installations():
    """Check if required libraries are installed"""
    print("Checking installations...")
    
    libs = ['flask', 'numpy', 'pandas', 'scapy', 'netifaces', 'psutil']
    missing = []
    
    for lib in libs:
        try:
            __import__(lib)
            print(f"  ✓ {lib}")
        except ImportError:
            print(f"  ✗ {lib} - NOT INSTALLED")
            missing.append(lib)
    
    if missing:
        print("\n[WARNING] Missing libraries. Run:")
        print(f"python -m pip install {' '.join(missing)}")
        print("\nAlso install Nmap from: https://nmap.org/download.html")
        input("\nPress Enter to continue anyway...")
    
    print("\n✅ Installation check complete\n")

def main():
    print_header()
    check_installations()
    
    print("Starting Dashboard...")
    print("Open browser at: http://127.0.0.1:5000\n")
    print("Press Ctrl+C to stop\n")
    
    # Run dashboard
    from src.dashboard import app
    app.run(debug=True, host='127.0.0.1', port=5000)

if __name__ == "__main__":
    main()