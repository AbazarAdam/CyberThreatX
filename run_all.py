import subprocess
import time
import sys
import os

def run_services():
    print("[*] Starting CyberThreatX Unified Entry Point...")
    
    # Ensure logs dir exists
    if not os.path.exists('monitored_logs'):
        os.makedirs('monitored_logs')
        print("[+] Created monitored_logs directory")

    if not os.path.exists('config.py'):
        print("[!] config.py missing. Please copy config.example.py to config.py")
        sys.exit(1)

    try:
        print("[*] Launching Dashboard (http://localhost:5000)...")
        dashboard_proc = subprocess.Popen([sys.executable, "dashboard.py"])
        
        print("[*] Launching Log Watcher...")
        watcher_proc = subprocess.Popen([sys.executable, "watcher.py", "--watch-dir", "monitored_logs"])
        
        print("\n[+] Both services are running.")
        print("[+] Press Ctrl+C to stop all services.\n")
        
        while True:
            time.sleep(1)
            # Check if any process died
            if dashboard_proc.poll() is not None:
                print("[!] Dashboard process stopped.")
                break
            if watcher_proc.poll() is not None:
                print("[!] Watcher process stopped.")
                break
                
    except KeyboardInterrupt:
        print("\n[!] Stopping services...")
    finally:
        dashboard_proc.terminate()
        watcher_proc.terminate()
        print("[+] Services stopped.")

if __name__ == "__main__":
    run_services()
