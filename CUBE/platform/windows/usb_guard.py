import os
import time
from datetime import datetime
import json
import logging
import threading
import ctypes
from ctypes import wintypes
import win32gui
import win32con
import win32api
import string
from scanner_client import ScannerClient

# Configuration
SERVER_IP = "100.98.209.6:50051"
CERT_PATH = r"C:\Users\henri\Downloads\dev_server.crt"
LOG_FILE = r"C:\ProgramData\USBAutoScan\logs\usb_service.log"
MAX_PATH = 260

class USBGuardService:
    def __init__(self):
        self.running = True
        self.logger = self.setup_logging()
        self.sweep_lock = threading.Lock()
        self.client = ScannerClient(
            server_address=SERVER_IP,
            cert_path=CERT_PATH if os.path.exists(CERT_PATH) else None,
            logger=self.logger
        )
        self.active_shields = {}

    def setup_logging(self):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def on_device_change(self, hwnd, msg, wparam, lparam):
        # Only trigger on Arrival (0x8000)
        if msg == win32con.WM_DEVICECHANGE and wparam == 0x8000:
            if not self.sweep_lock.locked():
                self.logger.info("New Hardware. Starting Sweep...")
                threading.Thread(target=self.global_lockdown_and_scan, daemon=True).start()
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def find_free_letter(self):
        """Finds an available drive letter starting from Z: downwards."""
        import string
        existing = win32api.GetLogicalDriveStrings().split('\000')
        for letter in reversed(string.ascii_uppercase):
            drive = f"{letter}:"
            if drive not in existing:
                return drive
        return None

    def create_hidden_window(self):
        """Creates a hidden window to receive WM_DEVICECHANGE messages."""
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = self.on_device_change 
        wc.lpszClassName = "USBGuardListener"
        hinst = wc.hInstance = win32api.GetModuleHandle(None)
        
        try:
            classAtom = win32gui.RegisterClass(wc)
            self.hwnd = win32gui.CreateWindow(
                classAtom, "USBGuardListener", 0, 0, 0, 0, 0, 0, 0, hinst, None
            )
            self.logger.info("Event listener initialized. Waiting for hardware signals...")
        except Exception as e:
            self.logger.error(f"Failed to create event window: {e}")
            self.running = False

    def trigger_ui_notification(self, drive, status, msg):
        event_path = r"C:\ProgramData\USBAutoScan\events\event.json"
        os.makedirs(os.path.dirname(event_path), exist_ok=True)
        data = {"drive": drive, "status": status, "message": msg, "ts": time.time()}
        try:
            with open(event_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logging.error(f"Failed to write event.json: {e}")

    def global_lockdown_and_scan(self):
        """Scans removable drives directly as they are detected."""
        with self.sweep_lock:
            self.logger.info("New device detected. Starting scan...")
            time.sleep(1)
            
            current_removable = self.get_removable_drives()

            for drive in current_removable:
                drive_path = drive + "\\"
                self.logger.info(f"SCANNING: {drive_path}")
                self.trigger_ui_notification(drive, "SCANNING", f"Scanning {drive}...")

                try:
                    # Check if we can actually see the drive
                    if os.path.exists(drive_path):
                        # Perform the scan directly on F:\ or G:\
                        self.logger.info(f"Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
                        self.client.scan_directory(drive_path)
                        self.logger.info(f"COMPLETED: {drive}")
                        self.trigger_ui_notification(drive, "CLEAN", f"Scan finished for {drive}")
                    else:
                        self.logger.warning(f"Drive {drive} detected but not accessible.")
                except Exception as e:
                    self.logger.error(f"Error scanning {drive}: {e}")
                finally:
                    self.logger.info(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")

    def verify_files_present(self, path):
        """Enhanced check to see past the Windows lock."""
        try:
            # Force a directory refresh
            ctypes.windll.kernel32.GetFileAttributesW(path)
            items = os.listdir(path)
            
            # Ignore System Volume Information and $RECYCLE.BIN
            real_files = [i for i in items if not i.startswith('$') and 'System Volume' not in i]
            
            return len(real_files) > 0
        except Exception as e:
            return False

    def acquire_shield(self, drive_letter):
        drive_path = f"\\\\.\\{drive_letter}"
        # Change access to FILE_READ_ATTRIBUTES (0x80) instead of GENERIC_READ (0x80000000)
        # during the initial lock to allow the OS to keep the mount alive.
        handle = ctypes.windll.kernel32.CreateFileW(
            drive_path, 
            0x80, # FILE_READ_ATTRIBUTES
            0x00000001, # FULL SHARE
            None, 3, 0, None
        )
        
        if handle != -1:
            bytes_ret = wintypes.DWORD(0)
            # Try to Lock. If it fails, we still have a handle to track it.
            ctypes.windll.kernel32.DeviceIoControl(
                handle, 0x00090018, None, 0, None, 0, ctypes.byref(bytes_ret), None
            )
        return handle

    def get_removable_drives(self):
        drives = set()
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(65 + i) + ":"
                # 2 = DRIVE_REMOVABLE
                if ctypes.windll.kernel32.GetDriveTypeW(letter + "\\") == 2:
                    drives.add(letter)
        return drives
    
    def run(self):
        self.create_hidden_window()
        if self.running:
            self.logger.info("Service Online. Waiting for USB events...")
            win32gui.PumpMessages() # This MUST stay here to catch signals

if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        USBGuardService().run()
    else:
        print("CRITICAL: This script must be run as Administrator.")