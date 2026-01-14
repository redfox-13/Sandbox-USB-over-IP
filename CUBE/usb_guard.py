import threading
import subprocess
import os
import time
import pyudev
import glob
from datetime import datetime
# We import everything from the client file
from scanner_client import ScannerClient, LogLevel, get_timestamp

# Configuration
MOUNT_BASE = "/mnt/usb_scanner"
SERVER_ADDRESS = "localhost:50051"
LOG_LEVEL = LogLevel.WARN

hardware_lock = threading.Lock()

def process_disk_session(parent_node, partitions):
    """Handles a USB stick session with a final summary."""
    with hardware_lock:
        session_start = get_timestamp()
        all_infected_files = []
        
        print(f"\n" + "="*60)
        print(f"🛡️  NEW HARDWARE SESSION: {parent_node}")
        print(f"🕒 Started at: {session_start}")
        print("="*60)
        
        client = ScannerClient(server_address=SERVER_ADDRESS, log_level=LOG_LEVEL)
        
        # 1. Hardware Read-Only Lock
        try:
            subprocess.run(['blockdev', '--setro', parent_node], check=True)
        except Exception as e:
            print(f"⚠️  Could not set read-only on {parent_node}: {e}")

        for dev_node in partitions:
            mount_path = os.path.join(MOUNT_BASE, os.path.basename(dev_node))
            
            try:
                # 2. Mount
                os.makedirs(mount_path, exist_ok=True)
                print(f"\n📦 Mounting {dev_node}...")
                subprocess.run(['mount', '-o', 'ro,nosuid,nodev', dev_node, mount_path], check=True)

                # 3. Scan
                print(f"🚀 Scanning Partition: {dev_node}")
                found_threats = client.scan_directory(mount_path)
                
                # Collect threats for the summary
                for threat in found_threats:
                    all_infected_files.append(f"{dev_node}: {threat}")

            except Exception as e:
                print(f"❌ Error processing {dev_node}: {e}")
            finally:
                # 4. Cleanup
                print(f"⏏️  Unmounting {mount_path}...")
                subprocess.run(['umount', '-l', mount_path], check=False)
                try:
                    if os.path.exists(mount_path):
                        os.rmdir(mount_path)
                except:
                    pass

        # --- THE FINAL SUMMARY ---
        session_end = get_timestamp()
        print("\n" + "█"*60)
        print(f"📊 USB SCAN SUMMARY: {parent_node}")
        print(f"🕒 Start: {session_start}")
        print(f"🕒 End:   {session_end}")
        start_dt = datetime.strptime(session_start, "%Y-%m-%dT%H:%M:%S.%f")
        end_dt = datetime.strptime(session_end, "%Y-%m-%dT%H:%M:%S.%f")
        duration = end_dt - start_dt
        print(f"🕒 Total Scan Time: {duration.total_seconds():.2f} seconds")
        print(f"☣️  Threats Detected: {len(all_infected_files)}")
        
        if all_infected_files:
            print("-" * 60)
            for item in all_infected_files:
                print(f"  [!] {item}")
        else:
            print("  ✅ CLEAN: No threats found during this session.")
        print("█"*60 + "\n")

def monitor_usb():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block', device_type='disk')

    print(f"🔍 USB Guard Active. Monitoring... (Log Level: {LOG_LEVEL.name})")

    for device in iter(monitor.poll, None):
        if device.action == 'add':
            dev_node = device.device_node
            print(f"\n⚡ Disk detected: {dev_node}. Waiting for partitions...")
            
            partitions = []
            for _ in range(5):
                time.sleep(1)
                partitions = glob.glob(f"{dev_node}[0-9]*")
                if partitions: break
            
            if not partitions:
                partitions = [dev_node]
                
            threading.Thread(
                target=process_disk_session, 
                args=(dev_node, partitions), 
                daemon=True
            ).start()

if __name__ == "__main__":
    if not os.path.exists(MOUNT_BASE):
        os.makedirs(MOUNT_BASE)
    monitor_usb()
