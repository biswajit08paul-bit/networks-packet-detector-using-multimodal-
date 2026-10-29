"""
Main entry point for the Real-Time IDS.

Usage:
    python run_ids.py
    (Tip: Run terminal as Administrator for raw promiscuous packet sniffing)

This starts the Flask dashboard at http://127.0.0.1:5000.
Select a network interface, click Start Monitoring, and watch live:
  - per-device packet/byte counts,
  - ML-based flow classification (trained on TON_IoT),
  - behavior-based scanning/flood alerts.
"""

import os
import sys
import ctypes

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add project root to path so we can import src.* modules
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure src/ can be imported as a package
SRC_PATH = os.path.join(PROJECT_ROOT, 'src')
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

if __name__ == '__main__':
    # Verify imports work
    try:
        from src.live_capture import LiveCapture
        from src.dashboard import app, capture
        print("[+] Imports successful")
    except ImportError as e:
        print(f"[-] Import error: {e}")
        print("Ensure you're running from the project root and all modules exist.")
        sys.exit(1)

    # Check Windows admin privileges
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    # List available network interfaces
    cap = LiveCapture()
    ifaces = cap.get_interfaces()

    print("\n" + "=" * 60)
    print("  REAL-TIME INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    if is_admin:
        print("[✓] Running with Administrator privileges (Full Npcap Sniffing Active)")
    else:
        print("[!] Notice: Running in Standard Mode (non-admin).")
        print("    Tip: Run terminal as Administrator for full raw deep-packet inspection.")
    print("-" * 60)
    print("Available network interfaces:")
    for i, iface_item in enumerate(ifaces):
        tag = " (Recommended - Active IP)" if iface_item['ip'] and iface_item['ip'] != '127.0.0.1' else ""
        print(f"  [{i}] {iface_item['name']}{tag}")
        print(f"      IP: {iface_item['ip'] or 'None'} | MAC: {iface_item['mac'] or 'None'} | {iface_item['description'] or ''}")

    default_idx = 0
    sel = input(f"\nSelect interface number [default: {default_idx}]: ").strip()
    selected_iface = None
    if sel.isdigit() and 0 <= int(sel) < len(ifaces):
        selected_iface = ifaces[int(sel)]['name']
    elif ifaces:
        selected_iface = ifaces[default_idx]['name']

    print(f"\n[*] Selected interface: {selected_iface}")
    print("[*] Starting dashboard at http://127.0.0.1:5000")
    print("[*] Open that URL in your browser, then click Start Monitoring.")
    print("[*] Press Ctrl+C to stop.\n" + "=" * 60 + "\n")

    if selected_iface:
        capture.interface = selected_iface
    app.run(debug=False, host='127.0.0.1', port=5000)
