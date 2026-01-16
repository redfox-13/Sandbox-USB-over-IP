import os
import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TICKET_DIR = "/run/usb_scanner"

class TicketHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.src_path.endswith(".json"):
            # When a JSON is dropped, launch the GUI
            subprocess.run(['python3', '/opt/usb_scanner/usb_resolver.py', event.src_path])

if __name__ == "__main__":
    os.makedirs(TICKET_DIR, exist_ok=True)
    event_handler = TicketHandler()
    observer = Observer()
    observer.schedule(event_handler, TICKET_DIR, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
