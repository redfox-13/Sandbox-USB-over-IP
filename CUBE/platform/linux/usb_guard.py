import threading
import subprocess
import os
import time
import pyudev
import glob
import logging
import fcntl
import json
from datetime import datetime
# We import everything from the client file
from scanner_client import ScannerClient, LogLevel

# Configuration
MOUNT_BASE = "/mnt/usb_scanner"
SERVER_ADDRESS = "localhost:50051"
LOG_LEVEL = LogLevel.BAD_ONLY
CERT_FILE = "/opt/usb_scanner/certs/dev_server.crt"

hardware_lock = threading.Lock()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('scanner_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def trigger_event(event_type, device, message):
    event_data = {
        "event": event_type,   # e.g., "BLOCK" or "SERVER_OFFLINE"
        "device": device,
        "message": message
    }
    # Write to the shared run directory
    with open('/run/usb_scanner/event.json', 'w') as f:
        json.dump(event_data, f)

def remount_for_user(dev_node, label):
    """Standard mount for user access."""
    user = subprocess.check_output(['stat', '-c', '%U', '/dev/console']).decode().strip()
    mount_path = f"/media/{user}/{label}"

    os.makedirs(mount_path, exist_ok=True)
    # Give ownership to the user so they can write to it
    subprocess.run(['mount', '-o', f'rw,nosuid,nodev,uid={user}', dev_node, mount_path], check=True)
    logger.info(f"Device {dev_node} is now available at {mount_path}")

def process_disk_session(parent_node, partitions):
    with hardware_lock:
        session_start = time.time()
        
        # 1. IMMEDIATE HARDWARE LOCK (Safety First)
        try:
            subprocess.run(['blockdev', '--setro', parent_node], check=True)
            logger.info(f"Hardware Write-Protection ENABLED for {parent_node}")
        except Exception as e:
            logger.error(f"CRITICAL: Could not lock {parent_node}: {e}")
            return 

        # 2. SERVER CHECK (Fail-Safe)
        # Check if cert exists before passing it
        current_cert = CERT_FILE if os.path.exists(CERT_FILE) else None
        client = ScannerClient(server_address=SERVER_ADDRESS, logger=logger, cert_path=current_cert)

        logger.info("Verifying CUBE Scanner Server status...")
        if not client.is_server_alive(timeout=4):
            logger.critical("SECURITY BREACH PREVENTED: Scanner Server is OFFLINE.")

            # Keep hardware locked and notify the user
            trigger_event(
                "Security Offline",
                parent_node,
                "Scanning server unreachable. USB remains locked."
            )
            return # EXIT: Do not proceed to mount or scan

        # 3. PROCEED TO SCAN (Only if server is alive)
        all_infected_files = []
        for dev_node in partitions:
            mount_path = os.path.join(MOUNT_BASE, os.path.basename(dev_node))

            try:
                # 3. SECURE MOUNT (Added noexec/nosuid for safety)
                os.makedirs(mount_path, exist_ok=True)
                logger.info(f"Mounting {dev_node} in Secure Zone...")
                subprocess.run([
                    'mount', '-o', 'ro,noexec,nosuid,nodev', 
                    dev_node, mount_path
                ], check=True)

                # 4. SCAN
                logger.info(f"Starting Partition scan: {dev_node}")
                found_threats = client.scan_directory(mount_path)
                
                for threat in found_threats:
                    clean_threat = threat.strip()
                    all_infected_files.append(f"{dev_node}: {clean_threat}")

            except Exception as e:
                logger.error(f"Error processing {dev_node}: {e}")
            finally:
                # 5. SECURE UNMOUNT (Cleanup scan mount before decision)
                logger.info(f"Unmounting {mount_path} from Secure Zone...")
                subprocess.run(['umount', '-l', mount_path], check=False)
                try:
                    if os.path.exists(mount_path):
                        os.rmdir(mount_path)
                except:
                    pass

        # --- THE FINAL SUMMARY ---
        session_end = time.time()
        # No more datetime.strptime! Just simple subtraction.
        duration = session_end - session_start

        logger.info(f"USB SCAN SUMMARY: {parent_node}")
        logger.info(f"Duration: {duration:.2f}s | Threats: {len(all_infected_files)}")

    if all_infected_files:
        os.makedirs("/run/usb_scanner", exist_ok=True)
        ticket_path = f"/run/usb_scanner/{os.path.basename(parent_node)}.json"
        
        ticket_data = {
            "parent_node": parent_node,
            "partitions": partitions,
            "threats": all_infected_files,
            "timestamp": session_end  # Store as Unix float for the resolver
        }

        with open(ticket_path, 'w') as f:
            json.dump(ticket_data, f)
        # 2. IMPORTANT: Permissions
        # Allow the 'watcher.py' (running as user) to read and delete this ticket
        os.chmod(ticket_path, 0o666)

        # 3. LEAVE HARDWARE LOCKED
        # We do NOT run 'blockdev --setrw' here. 
        # The device stays in Read-Only mode at the kernel level.

        trigger_event(
            "USB Blocked",
            parent_node,
            f"Threats found on {parent_node}. Open USB resolver."
        )
    else:
        # CLEAN PATH: Immediate Hand-off
        logger.info(f"No threats on {parent_node}. Unlocking for user.")

        # Unlock hardware
        subprocess.run(['blockdev', '--setrw', parent_node], check=True)

        # Remount in user-space
        for dev_node in partitions:
            label = os.path.basename(dev_node)
            remount_for_user(dev_node, label)

        trigger_event("USB Ready", parent_node, "Scan complete. No threats found.")

def monitor_usb():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block', device_type='disk')

    logger.info(f"USB Guard Active. Monitoring... (Log Level: {LOG_LEVEL.name})")

    for device in iter(monitor.poll, None):
        if device.action == 'add':
            dev_node = device.device_node
            logger.info(f"\nDisk detected: {dev_node}. Waiting for partitions...")

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
