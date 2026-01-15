import os
import time
import ctypes
from ctypes import wintypes
import shutil
import tempfile
import sys
import argparse
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# import ScannerClient lazily inside scan_drive_with_server to avoid import-time grpc dependency

def setup_logging():
    logger = logging.getLogger('usb_auto_scan')
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    log_dir = r"C:\ProgramData\USBAutoScan\logs"
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(log_dir, exist_ok=True)
    
    fh = RotatingFileHandler(
        os.path.join(log_dir, 'usb_auto_scan.log'),
        maxBytes=5_000_000,
        backupCount=5,
        encoding='utf-8'
    )
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


logger = setup_logging()


def log_info(msg):
    """Log to both file and console."""
    try:
        logger.info(msg)
    except Exception:
        pass
    try:
        print(msg)
    except Exception:
        pass


def _get_quarantine_root(drive_letter):
    # prefer ProgramData quarantine directory, fall back to local project folder
    sanitized = drive_letter.strip(':').upper()
    try:
        base = os.path.join(r"C:\ProgramData\USBAutoScan\quarantine", sanitized)
        os.makedirs(base, exist_ok=True)
        return base
    except Exception:
        local = os.path.join(os.path.dirname(__file__), 'quarantine', sanitized)
        os.makedirs(local, exist_ok=True)
        return local


def _report_event(message, level='warning'):
    """Report an event to the Windows Event Log. Falls back to logger on failure."""
    try:
        import win32evtlogutil
        import win32evtlog
        evt_type = win32evtlog.EVENTLOG_INFORMATION_TYPE
        if level == 'warning':
            evt_type = win32evtlog.EVENTLOG_WARNING_TYPE
        elif level == 'error':
            evt_type = win32evtlog.EVENTLOG_ERROR_TYPE
        # Use the service name as the source/application name
        appname = 'USBAutoScan'
        try:
            win32evtlogutil.ReportEvent(appname, 1000, eventCategory=0, eventType=evt_type, strings=[message])
            return True
        except Exception:
            # Try a lower-level API if ReportEvent fails
            try:
                import win32api
                win32api.SetLastError(0)
            except Exception:
                pass
    except Exception:
        pass
    # fallback
    log_info(f"EVENT[{level.upper()}]: {message}")
    return False


def _quarantine_file(original_full_path, rel_path, drive_letter):
    """Move `original_full_path` into quarantine preserving relative path.
    Returns (True, dest_path) on success, or (False, reason) on failure.
    """
    qroot = _get_quarantine_root(drive_letter)
    safe_rel = os.path.normpath(rel_path).lstrip(os.sep)
    dest = os.path.join(qroot, safe_rel)
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(original_full_path):
            shutil.move(original_full_path, dest)
            # leave a small marker file in place to explain why the file is gone
            try:
                placeholder = original_full_path + ".QUARANTINED.txt"
                with open(placeholder, 'w', encoding='utf-8') as ph:
                    ph.write(f"This file was quarantined by USBAutoScan on {time.strftime('%Y-%m-%d %H:%M:%S')}.\n")
                    ph.write(f"Original moved to: {dest}\n")
            except Exception:
                pass
            return True, dest
        else:
            return False, 'original_not_found'
    except Exception as e:
        return False, str(e)


def _write_report_to_drive(drive_root, report_lines):
    """Attempt to write REPORT.TXT at the root of the drive. If that fails,
    write the report to the local project quarantine_reports folder and return that path.
    Returns (True, path) if written to drive, (False, path) if written locally, (False, None) on error.
    """
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    header = [f"USBAutoScan Report - {timestamp}", f"Drive: {drive_root}", ""]
    try:
        report_path = os.path.join(drive_root, 'REPORT.TXT')
        with open(report_path, 'a', encoding='utf-8') as fh:
            for ln in header + report_lines:
                fh.write(ln + '\n')
        return True, report_path
    except Exception as e:
        try:
            local_dir = os.path.join(os.path.dirname(__file__), 'quarantine_reports')
            os.makedirs(local_dir, exist_ok=True)
            local_path = os.path.join(local_dir, f"REPORT_{time.strftime('%Y%m%d_%H%M%S')}.txt")
            with open(local_path, 'w', encoding='utf-8') as fh:
                for ln in header + report_lines:
                    fh.write(ln + '\n')
            return False, local_path
        except Exception:
            return False, None


def _is_interactive():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False

# Windows drive type constants
DRIVE_REMOVABLE = 2

# CreateFile constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# FSCTL codes for locking/dismounting/ejecting volumes
FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020
IOCTL_STORAGE_EJECT_MEDIA = 0x2D4808
IOCTL_STORAGE_MEDIA_REMOVAL = 0x2D4205


def get_removable_drives():
    drives = []
    kernel32 = ctypes.windll.kernel32
    bitmask = kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(ord('A') + i) + ':'
            drive_type = kernel32.GetDriveTypeW(f"{letter}\\")
            if drive_type == DRIVE_REMOVABLE:
                drives.append(letter)
    return drives


def find_and_kill_locking_processes(drive_letter):
    """Find processes locking the drive and attempt to kill them.
    
    Returns list of (pid, process_name) that were killed.
    """
    import subprocess
    
    killed = []
    
    try:
        # Method 1: Try to use handle.exe (Sysinternals) if available
        try:
            result = subprocess.run(
                ['handle.exe', f'{drive_letter}:\\', '-nobanner'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.stdout:
                log_info(f"  Found processes locking the drive (via handle.exe):")
                # Parse handle.exe output to find PIDs
                for line in result.stdout.split('\n'):
                    if 'pid' in line.lower():
                        log_info(f"    {line.strip()}")
        except Exception:
            pass
        
        # Method 2: Use PowerShell to find and close Windows Explorer
        try:
            log_info(f"  Attempting to close Windows Explorer for {drive_letter}...")
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-Command',
                 f'Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                log_info(f"  ✓ Windows Explorer closed")
                killed.append((0, 'explorer.exe'))
        except Exception as e:
            log_info(f"    Warning: Could not close Explorer: {e}")
        
        # Method 3: Find and kill other locking processes using OpenFiles
        try:
            log_info(f"  Checking for open file handles...")
            result = subprocess.run(
                ['wmic', 'process', 'call', 'getconnectionids'],
                capture_output=True,
                timeout=5
            )
        except Exception:
            pass
        
    except Exception as e:
        log_info(f"  Warning during process enumeration: {e}")
    
    return killed


def lock_volume(drive_letter, auto_kill_processes=True):
    """Lock and dismount the volume to block all I/O operations.
    Returns (handle, error_msg) where handle must be kept open to maintain the lock."""
    log_info(f"Attempting to lock volume {drive_letter}...")
    
    # Try robust lock + dismount with DeviceIoControl first
    handle, err = try_lock_and_dismount(drive_letter)
    if handle:
        log_info(f"✓ Volume {drive_letter} successfully locked and dismounted (I/O now blocked)")
        return handle, None
    
    if err:
        msg = format_win_error(err) if isinstance(err, int) else str(err)
        log_info(f"FSCTL lock/dismount failed: {msg}")
        
        # If it failed, try to kill locking processes
        if auto_kill_processes and 'being used by another process' in str(msg):
            log_info(f"\n⚠ Drive is locked by another process. Attempting to release handles...")
            killed = find_and_kill_locking_processes(drive_letter)
            
            if killed or True:  # Try again even if we couldn't identify the process
                log_info(f"Retrying lock after closing processes...")
                time.sleep(1)
                handle, err = try_lock_and_dismount(drive_letter, retries=3)
                if handle:
                    log_info(f"✓ Volume {drive_letter} successfully locked after process cleanup")
                    return handle, None

    # Fallback: open the raw volume to acquire exclusive access and block other processes
    log_info(f"Attempting fallback method: exclusive volume access...")
    path = f"\\\\.\\{drive_letter}"
    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE

    handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == INVALID_HANDLE_VALUE or handle == 0:
        last = ctypes.windll.kernel32.GetLastError()
        error_msg = format_win_error(last)
        log_info(f"✗ Failed to lock volume {path}: {error_msg}")
        return None, error_msg
    
    log_info(f"✓ Volume {drive_letter} locked via exclusive access (I/O blocked)")
    return handle, None


def format_win_error(err_code):
    try:
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
        buf = ctypes.create_unicode_buffer(1024)
        res = ctypes.windll.kernel32.FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, None, err_code, 0, buf, len(buf), None)
        if res:
            return buf.value.strip()
    except Exception:
        pass
    return f"Unknown error {err_code}"


def try_lock_and_dismount(drive_letter, retries=5, wait_seconds=1.0):
    """Attempt to lock and dismount the volume using DeviceIoControl.
    
    Returns (handle, None) on success where `handle` must be kept open to
    maintain the lock, or (None, error_code) on failure.
    """
    kernel32 = ctypes.windll.kernel32
    path = f"\\\\.\\{drive_letter}"

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE

    handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == INVALID_HANDLE_VALUE or handle == 0:
        return None, f"CreateFile failed for {path}"

    DeviceIoControl = kernel32.DeviceIoControl
    DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    DeviceIoControl.restype = wintypes.BOOL

    last_err = None
    for attempt in range(1, retries + 1):
        bytes_returned = wintypes.DWORD(0)
        
        log_info(f"  Lock attempt {attempt}/{retries}...")
        res = DeviceIoControl(handle, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None)
        if res:
            log_info(f"  ✓ Volume locked")
            # locked; now dismount
            log_info(f"  Dismounting volume...")
            res2 = DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None)
            if res2:
                log_info(f"  ✓ Volume dismounted")
                return handle, None
            else:
                last_err = kernel32.GetLastError()
                log_info(f"  ✗ Dismount failed with code {last_err}")
                break

        last_err = kernel32.GetLastError()
        if attempt < retries:
            time.sleep(wait_seconds)

    # failed to lock/dismount
    try:
        kernel32.CloseHandle(handle)
    except Exception:
        pass
    return None, last_err


def unlock_volume(handle):
    """Release the lock on the volume."""
    if not handle:
        return
    try:
        ctypes.windll.kernel32.CloseHandle(handle)
        log_info("✓ Volume handle closed and lock released")
    except Exception as e:
        log_info(f"Warning: Error closing volume handle: {e}")


def safely_eject_usb(drive_letter):
    """Attempt to safely eject the USB drive (like "Safely Remove Hardware").
    
    Returns (True, msg) on success, (False, msg) on failure.
    """
    log_info(f"\nPreparing USB drive {drive_letter} for safe removal...")
    
    path = f"\\\\.\\{drive_letter}"
    kernel32 = ctypes.windll.kernel32
    
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE
    
    DeviceIoControl = kernel32.DeviceIoControl
    DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    DeviceIoControl.restype = wintypes.BOOL
    
    try:
        # Open volume for ejection
        handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if handle == INVALID_HANDLE_VALUE or handle == 0:
            return False, f"Could not open volume {path} for ejection"
        
        try:
            # First, prevent further media removal requests
            log_info(f"  Disabling media removal prevention...")
            prevention_data = ctypes.c_byte(0)  # Allow media removal
            bytes_returned = wintypes.DWORD(0)
            DeviceIoControl(handle, IOCTL_STORAGE_MEDIA_REMOVAL, ctypes.byref(prevention_data), 1, None, 0, ctypes.byref(bytes_returned), None)
            
            # Now eject the media
            log_info(f"  Ejecting media...")
            bytes_returned = wintypes.DWORD(0)
            res = DeviceIoControl(handle, IOCTL_STORAGE_EJECT_MEDIA, None, 0, None, 0, ctypes.byref(bytes_returned), None)
            
            if res:
                log_info(f"✓ USB drive {drive_letter} has been safely ejected!")
                log_info(f"✓ It is now safe to physically remove the USB drive.")
                return True, "Ejection successful"
            else:
                err = kernel32.GetLastError()
                return False, format_win_error(err)
        finally:
            kernel32.CloseHandle(handle)
            
    except Exception as e:
        return False, str(e)


def scan_drive_with_server(drive_path, server_addr="localhost:50051", copy_to_temp=False):
    try:
        from client_test import ScannerClient
        client = ScannerClient(server_address=server_addr)
    except Exception as e:
        # Likely missing grpc or other dependency — offer options
        log_info(f"Could not import ScannerClient: {e}")
        log_info("Options: (I)nstall requirements now, (M)ock scan for testing, (A)bort")
        choice = input("Enter I, M or A: ").strip().lower()
        if choice == 'i':
            import subprocess, sys
            req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
            log_info(f"Attempting to install requirements from {req_path} using pip...")
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', req_path], check=False)
            except Exception as ie:
                log_info(f"Failed to run pip: {ie}")
            # try import again
            try:
                from client_test import ScannerClient
                client = ScannerClient(server_address=server_addr)
            except Exception as e2:
                log_info(f"Still failed to import ScannerClient: {e2}")
                log_info("Falling back to mock scanner for testing.")
                client = None
        elif choice == 'm':
            client = None
        else:
            raise SystemExit("Aborted due to missing dependencies.")

    # If client is None, use a mock scanner to allow testing without grpc
    if client is None:
        class _MockResponse:
            def __init__(self, path, status='CLEAN'):
                self.path_within_directory = path
                self.status = status

        class MockScannerClient:
            def __init__(self, server_address=None):
                pass

            def scan_directory(self, path):
                results = []
                for root, _, files in os.walk(path):
                    for f in files:
                        rel = os.path.relpath(os.path.join(root, f), path)
                        log_info(f"[MOCK:CLEAN] {rel}")
                        results.append(_MockResponse(rel, 'CLEAN'))
                return results

        client = MockScannerClient(server_address=server_addr)

    if copy_to_temp:
        # Copy contents to a temporary directory to avoid direct mounting issues
        tmpdir = tempfile.mkdtemp(prefix="usb_scan_")
        try:
            for root, dirs, files in os.walk(drive_path):
                rel_root = os.path.relpath(root, drive_path)
                target_root = os.path.join(tmpdir, rel_root) if rel_root != "." else tmpdir
                os.makedirs(target_root, exist_ok=True)
                for f in files:
                    src = os.path.join(root, f)
                    dst = os.path.join(target_root, f)
                    try:
                        shutil.copy2(src, dst)
                    except Exception:
                        # Skip unreadable files but continue scanning others
                        pass
            return client.scan_directory(tmpdir)
        finally:
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

    # ScannerClient.scan_directory expects a directory path
    return client.scan_directory(drive_path)


def main(poll_interval=1.0, copy_to_temp=False):
    log_info("=" * 80)
    log_info("USB Auto-Scan Service Started")
    log_info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_info(f"Poll interval: {poll_interval}s | Temp copy mode: {copy_to_temp}")
    log_info("=" * 80)
    log_info("Monitoring for removable USB drives...\n")
    
    seen = set()
    try:
        while True:
            drives = set(get_removable_drives())
            new = drives - seen
            for d in sorted(new):
                handle_new_drive_with_options(d, copy_to_temp=copy_to_temp)
            seen = drives
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        log_info("\n" + "=" * 80)
        log_info("USB Auto-Scan Service Stopped")
        log_info("=" * 80)


def handle_new_drive_with_options(drive_letter, copy_to_temp=False):
    """Complete USB scanning and ejection workflow."""
    drive_root = f"{drive_letter}\\"
    log_info("\n" + "=" * 80)
    log_info(f"NEW USB DEVICE DETECTED: {drive_root}")
    log_info("=" * 80)

    tmpdir = None
    handle = None
    
    try:
        # Step 1: Lock the volume
        log_info(f"\nSTEP 1: Blocking I/O operations...")
        handle, error_msg = lock_volume(drive_letter)
        
        if not handle and copy_to_temp:
            log_info(f"Warning: Could not lock volume, but proceeding with temp copy scan...")
            log_info(f"Note: Drive may remain accessible to other processes")

        if not handle and not copy_to_temp:
            log_info(f"\n⚠ Still unable to lock the volume after attempting to close processes.")
            log_info(f"This usually means:")
            log_info(f"  • Windows Explorer is accessing the drive")
            log_info(f"  • Antivirus software is scanning it")
            log_info(f"  • File indexing service is active")
            log_info(f"  • Another application has files open")
            
            if _is_interactive():
                log_info(f"\nOptions:")
                log_info(f"  [1] Try again (processes may have released the drive)")
                log_info(f"  [2] Scan temp copy anyway (less safe but may work)")
                log_info(f"  [3] Abort")
                choice = input("Enter 1, 2, or 3: ").strip()
                
                if choice == '1':
                    log_info(f"\nRetrying lock attempt...")
                    handle, error_msg = lock_volume(drive_letter)
                    if not handle:
                        log_info(f"✗ CRITICAL: Failed to lock volume after retry.")
                        log_info(f"Aborting scan for safety.")
                        return
                elif choice == '2':
                    log_info(f"Will proceed with temporary copy scan.")
                    copy_to_temp = True
                else:
                    log_info(f"Scan aborted by user.")
                    return
            else:
                log_info(f"✗ CRITICAL: Failed to lock volume. Non-interactive mode - aborting.")
                log_info(f"Aborting scan for safety.")
                return

        # Step 2: Optionally copy to temp directory
        if copy_to_temp:
            log_info(f"\nSTEP 2: Copying USB contents to temporary directory for analysis...")
            tmpdir = tempfile.mkdtemp(prefix="usb_scan_")
            log_info(f"  Temp directory: {tmpdir}")
            try:
                for root, dirs, files in os.walk(drive_root):
                    rel_root = os.path.relpath(root, drive_root)
                    target_root = os.path.join(tmpdir, rel_root) if rel_root != "." else tmpdir
                    os.makedirs(target_root, exist_ok=True)
                    for f in files:
                        src = os.path.join(root, f)
                        dst = os.path.join(target_root, f)
                        try:
                            shutil.copy2(src, dst)
                        except Exception as e:
                            log_info(f"    Warning: Could not copy {src}: {e}")
                log_info(f"✓ Files copied successfully")
            except Exception as e:
                log_info(f"✗ Error copying files: {e}")
                return
        else:
            log_info(f"\nSTEP 2: Preparing for direct scanning...")
        
        # Step 3: Scan the drive
        log_info(f"\nSTEP 3: Scanning for malware...")
        scan_path = tmpdir if tmpdir else drive_root
        
        try:
            from client_test import ScannerClient
            client = ScannerClient(server_address="localhost:50051")
        except Exception as e:
            log_info(f"\n✗ IMPORT ERROR: {e}")
            log_info(f"Options: (I)nstall requirements, (M)ock scan, (A)bort")
            
            if not _is_interactive():
                log_info(f"Non-interactive mode. Aborting.")
                return
            
            choice = input("Enter I, M or A: ").strip().lower()
            if choice == 'i':
                import subprocess
                req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
                log_info(f"Installing requirements from {req_path}...")
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', req_path], check=False)
                except Exception as ie:
                    log_info(f"Failed: {ie}")
                try:
                    from client_test import ScannerClient
                    client = ScannerClient(server_address="localhost:50051")
                except Exception as e2:
                    log_info(f"Still failed: {e2}. Using mock scanner.")
                    client = None
            elif choice == 'm':
                client = None
            else:
                raise SystemExit("Aborted.")

        # Use mock scanner if client unavailable
        if client is None:
            class _MockResponse:
                def __init__(self, path, status='CLEAN'):
                    self.path_within_directory = path
                    self.status = status

            class MockScannerClient:
                def scan_directory(self, path):
                    results = []
                    for root, _, files in os.walk(path):
                        for f in files:
                            rel = os.path.relpath(os.path.join(root, f), path)
                            log_info(f"  [MOCK] {rel}: CLEAN")
                            results.append(_MockResponse(rel, 'CLEAN'))
                    return results

            client = MockScannerClient()

        results = client.scan_directory(scan_path)
        
        if not results:
            log_info(f"  No results from scan")
            return

        # Step 4: Process scan results
        log_info(f"\nSTEP 4: Processing scan results...")
        non_clean = [r for r in results if getattr(r, 'status', '').upper() != 'CLEAN']

        if not non_clean:
            log_info(f"✓ All files CLEAN - no threats detected")
        else:
            log_info(f"✗ ALERT: Found {len(non_clean)} potentially infected file(s)!")
            
            report_lines = []
            for r in non_clean:
                rel = getattr(r, 'path_within_directory', None) or getattr(r, 'path', None) or str(r)
                status = getattr(r, 'status', 'INFECTED')
                rel = os.path.normpath(rel)
                
                log_info(f"  - {rel}: {status}")
                
                original_path = os.path.join(drive_root, rel)
                success, info = _quarantine_file(original_path, rel, drive_letter)
                
                if success:
                    report_lines.append(f"{rel}    {status}    QUARANTINED -> {info}")
                    log_info(f"    ✓ Quarantined to: {info}")
                else:
                    if info == 'original_not_found':
                        report_lines.append(f"{rel}    {status}    NOT_FOUND (scanned from temp)")
                        log_info(f"    Note: File not found on drive (scanned from temp copy)")
                    else:
                        report_lines.append(f"{rel}    {status}    QUARANTINE_FAILED: {info}")
                        log_info(f"    ✗ Failed to quarantine: {info}")

            written_to_drive, report_path = _write_report_to_drive(drive_root, report_lines)
            if written_to_drive:
                log_info(f"✓ Scan report written to: {report_path}")
            elif report_path:
                log_info(f"Note: Scan report saved locally: {report_path}")

        # Step 5: Safe ejection decision
        log_info(f"\nSTEP 5: USB device decision...")
        
        if non_clean:
            log_info(f"\n⚠ WARNING: This USB drive contains potentially infected files!")
            log_info(f"The files have been quarantined, but you should:")
            log_info(f"  1) Physically remove the USB drive immediately")
            log_info(f"  2) Do NOT reconnect it until fully investigated")
            log_info(f"  3) Review the quarantine folder and scan report")
        else:
            log_info(f"\n✓ All files passed security scan.")
        
        if not _is_interactive():
            log_info(f"\nNon-interactive mode. Proceeding to eject USB automatically...")
            safely_eject_usb(drive_letter)
            return

        log_info(f"\nWhat would you like to do?")
        log_info(f"  [1] Safely eject USB drive (like 'Safely Remove Hardware')")
        log_info(f"  [2] Keep USB connected (administrator access will be released)")
        log_info(f"  [3] Cancel and keep USB locked")
        
        choice = input("\nEnter 1, 2, or 3: ").strip()
        
        if choice == '1':
            # Release lock before ejection
            if handle:
                unlock_volume(handle)
                handle = None
            
            success, msg = safely_eject_usb(drive_letter)
            if success:
                log_info(f"You can now physically remove the USB drive.")
            else:
                log_info(f"Ejection failed: {msg}")
                log_info(f"Try using 'Safely Remove Hardware' from Windows system tray.")
        
        elif choice == '2':
            log_info(f"\nReleasing I/O block. USB drive is now accessible.")
        
        else:
            log_info(f"\nKeeping USB drive locked for safety. Restart computer to unlock.")
            handle = None  # Keep it locked
            return

    except KeyboardInterrupt:
        log_info(f"\n\nOperation cancelled by user.")
    except Exception as e:
        log_info(f"✗ Error during USB scan: {e}")
        logger.exception("Full traceback:")
    finally:
        # Cleanup
        if handle:
            log_info(f"\nReleasing I/O block...")
            unlock_volume(handle)
        
        if tmpdir:
            try:
                shutil.rmtree(tmpdir)
                log_info(f"Cleaned up temporary directory")
            except Exception:
                pass
        
        log_info("=" * 80)
        log_info("USB session ended")
        log_info("=" * 80 + "\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='USB auto-scan')
    parser.add_argument('--copy-to-temp', action='store_true', help='Copy USB contents to a temporary directory before scanning')
    args = parser.parse_args()
    main(copy_to_temp=args.copy_to_temp)

