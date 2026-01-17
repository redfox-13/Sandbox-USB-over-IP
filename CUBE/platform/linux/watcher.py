import os
import time
import subprocess
import json
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
TICKET_DIR = "/run/usb_scanner"
RESOLVER_BIN = "/opt/usb_scanner/usb_resolver.py"

# Logging setup for the user service
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

class CUBEHandler(FileSystemEventHandler):
    """
    Handles all filesystem events in the /run/usb_scanner directory.
    - event.json triggers a desktop notification.
    - any other .json triggers the GUI Resolver.
    """
    
    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, path):
        # 1. Distinguish between Notifications and GUI Tickets
        filename = os.path.basename(path)
        
        if filename == "event.json":
            self.handle_notification(path)
        elif filename.endswith(".json"):
            self.handle_gui_launch(path)

    def handle_notification(self, path):
        try:
            time.sleep(0.1)
            if not os.path.exists(path):
                return

            # We must open the file and define 'data' right here
            with open(path, "r") as f:
                data = json.load(f)
            
            # Now 'data' is defined in this scope
            event_name = data.get('event', 'Alert')
            device_name = data.get('device', 'USB')
            msg = data.get('message', 'Check security logs.')
            
            # Safe timestamp handling
            ts = data.get('timestamp', time.time())

            subprocess.run([
                'notify-send', 
                '-u', 'critical', 
                '-a', 'CUBE Security',
                f"{event_name}: {device_name}", 
                msg
            ])
            
            os.remove(path)
            
        except Exception as e:
            print(f"Notification Error: {e}")

    def handle_gui_launch(self, path):
        filename = os.path.basename(path)
        # Stricter check: Only launch for partition tickets, never event.json
        if filename == "event.json":
            return

        try:
            logger.info(f"Threat detected. Launching Resolver for: {path}")
            subprocess.Popen(['python3', RESOLVER_BIN, path])
        except Exception as e:
            logger.error(f"Failed to launch GUI: {e}")

if __name__ == "__main__":
    # Ensure directory exists and is accessible
    if not os.path.exists(TICKET_DIR):
        try:
            os.makedirs(TICKET_DIR, exist_ok=True)
            os.chmod(TICKET_DIR, 0o777)
        except PermissionError:
            logger.warning(f"Could not create {TICKET_DIR}. Relying on Guard to create it.")

    event_handler = CUBEHandler()
    observer = Observer()
    observer.schedule(event_handler, TICKET_DIR, recursive=False)
    
    logger.info(f"CUBE Watcher active. Monitoring {TICKET_DIR}...")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

