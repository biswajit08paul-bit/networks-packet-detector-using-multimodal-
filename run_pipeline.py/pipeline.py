"""
Complete Pipeline: Run all modules sequentially
"""

import os
import subprocess
import sys

def setup_environment():
    """Install requirements"""
    print("\n" + "="*60)
    print("STEP 1: Installing Requirements")
    print("="*60)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def create_directories():
    """Create necessary directories"""
    dirs = ['datasets', 'models', 'logs', 'templates']
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"[✓] Created {d}/")

def run_data_preparation():
    """Run data loader"""
    print("\n" + "="*60)
    print("STEP 2: Data Preparation")
    print("="*60)
    import data_loader
    print("[✓] Data loader ready")

def run_model_training():
    """Train models"""
    print("\n" + "="*60)
    print("STEP 3: Model Training")
    print("="*60)
    import train_model
    print("\n[✓] Model training complete")

def run_detection_engine():
    """Test detection engine"""
    print("\n" + "="*60)
    print("STEP 4: Testing Detection Engine")
    print("="*60)
    from detection_engine import DetectionEngine
    
    engine = DetectionEngine()
    engine.simulate_traffic(10)
    print("[✓] Detection engine test complete")

def run_dashboard():
    """Launch dashboard"""
    print("\n" + "="*60)
    print("STEP 5: Launching Dashboard")
    print("="*60)
    print("\n🌐 Dashboard URL: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop\n")
    
    import dashboard
    dashboard.app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" IoT INTRUSION DETECTION SYSTEM")
    print(" Complete Pipeline Execution")
    print("="*60)
    
    # Setup
    create_directories()
    
    # Run steps
    run_data_preparation()
    run_model_training()
    run_detection_engine()
    
    # Ask user if they want to launch dashboard
    response = input("\n🚀 Launch dashboard? (y/n): ")
    if response.lower() == 'y':
        run_dashboard()
    else:
        print("\n✅ Pipeline complete!")