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

def send_user_notification(title, message, urgency="normal"):
    try:
        # 1. Identify the active desktop user
        # We look for the user owning the current console
        user = subprocess.check_output(['stat', '-c', '%U', '/dev/console']).decode().strip()
        # 2. Find their UID (typically 1000)
        uid = subprocess.check_output(['id', '-u', user]).decode().strip()

        # 3. Define the critical environment variables
        # /run/user/UID/bus is the standard location on Arch/Hyprland
        runtime_dir = f"/run/user/{uid}"
        dbus_path = f"unix:path={runtime_dir}/bus"

        # 4. Build the command using 'sudo -u' to act as that user
        # We explicitly set the env vars so notify-send knows where to go
        cmd = [
            'sudo', '-u', user,
            f'DBUS_SESSION_BUS_ADDRESS={dbus_path}',
            f'XDG_RUNTIME_DIR={runtime_dir}',
            'DISPLAY=:0',           # Fallback for X11/XWayland
            'WAYLAND_DISPLAY=wayland-0', # Primary for Hyprland
            'notify-send',
            '-u', urgency,
            '-a', 'CUBE Security',  # App Name
            title, 
            message
        ]

        subprocess.run(cmd, check=False)

    except Exception as e:
        logger.error(f"Notification bridge failed: {e}")

def remount_for_user(dev_node, label):
    """Standard mount for user access."""
    user = subprocess.check_output(['stat', '-c', '%U', '/dev/console']).decode().strip()
    mount_path = f"/media/{user}/{label}"

    os.makedirs(mount_path, exist_ok=True)
    # Give ownership to the user so they can write to it
    subprocess.run(['mount', '-o', f'rw,nosuid,nodev,uid={user}', dev_node, mount_path], check=True)
    logger.info(f"Device {dev_node} is now available at {mount_path}")

def process_disk_session(parent_node, partitions):
    """Handles a USB stick session with a final summary and user-land handoff."""
    with hardware_lock:
        # Use Unix timestamp (float)
        session_start = time.time() 
        all_infected_files = []

        logger.info(f"NEW HARDWARE SESSION: {parent_node}")
        # 1. PREVENT AUTO-MOUNT: Tell udisks2 to ignore this device
        try:
            subprocess.run(['udisksctl', 'lock', '--block-device', parent_node], check=False)
        except Exception as e:
            logger.debug(f"udisksctl lock hint failed (non-critical): {e}")

        # 2. HARDWARE READ-ONLY LOCK
        try:
            subprocess.run(['blockdev', '--setro', parent_node], check=True)
            logger.info(f"Hardware Write-Protection ENABLED for {parent_node}")
        except Exception as e:
            logger.error(f"CRITICAL: Could not set read-only on {parent_node}: {e}")
            return # Safety exit if we can't lock the hardware

        client = ScannerClient(server_address=SERVER_ADDRESS, logger=logger, log_level=LOG_LEVEL)

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
                    all_infected_files.append(f"{dev_node}: {threat}")

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

        send_user_notification(
            "USB Blocked",
            f"Threats found on {parent_node}. Open USB resolver.",
            urgency="critical"
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

        send_user_notification("USB Ready", "Scan complete. No threats found.")

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
