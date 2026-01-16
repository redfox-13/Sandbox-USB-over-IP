import os
import json
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import subprocess

TICKET_DIR = "/run/usb_scanner"

class USBResolverApp:
    def __init__(self, ticket_path):
        self.ticket_path = ticket_path
        try:
            with open(ticket_path, 'r') as f:
                self.data = json.load(f)
        except Exception as e:
            print(f"Failed to load ticket: {e}")
            return
        
        # Convert Unix float to readable string
        dt_object = datetime.fromtimestamp(self.data['timestamp'])
        self.scan_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')

        self.root = tk.Tk()
        self.root.title("CUBE USB Security Resolver")
        self.root.geometry("550x450")
        self.setup_ui()

    def setup_ui(self):
        # Header
        tk.Label(self.root, text="⚠️ Threats Detected", font=("Arial", 14, "bold"), fg="#cc0000").pack(pady=(10, 2))
        tk.Label(self.root, text=f"Scan completed at: {self.scan_time}", font=("Arial", 9, "italic")).pack()
        
        info_frame = tk.Frame(self.root)
        info_frame.pack(pady=10)
        tk.Label(info_frame, text=f"Device: {self.data['parent_node']}", font=("Arial", 10, "bold")).pack()

        # Threat List
        tk.Label(self.root, text="Infected Files:").pack(anchor="w", padx=20)
        area = scrolledtext.ScrolledText(self.root, width=60, height=10, bg="#fdf6f6")
        area.pack(pady=5, padx=20)
        
        for threat in self.data['threats']:
            area.insert(tk.END, f"✖ {threat}\n")
        area.configure(state='disabled')

        # Actions
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=20)

        # "Clean & Mount" would trigger your hardware unlock script
        tk.Button(btn_frame, text="Clean & Authorize", 
                  command=self.resolve_issue, bg="#2e7d32", fg="white", 
                  width=20, height=2).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="Keep Blocked", 
                  command=self.root.destroy, width=15).pack(side=tk.LEFT, padx=10)

    def resolve_issue(self):
        """Placeholder for the cleaning and mounting logic."""
        # Here you would call your mount_helper.sh or sudo blockdev --setrw
        messagebox.showinfo("Action Required", "In a production CUBE setup, this would now trigger file deletion and hardware unlock.")
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        app = USBResolverApp(sys.argv[1])
        app.run()

