OPT_DIR = /opt/usb_scanner
SYSTEMD_ROOT = /etc/systemd/system
SYSTEMD_USER = /usr/lib/systemd/user
PROTO_DIR = ../../../proto
SERVER_DIR = ../../../SUSS/
CERT_FILE = dev_server.crt
CERT_DIR = $(OPT_DIR)/certs

.PHONY: all install uninstall configure check-deps cert-sync

all: configure

configure:
	@echo "--- Building gRPC Stubs ---"
	python3 -m venv .build_venv
	.build_venv/bin/pip install grpcio-tools protobuf > /dev/null
	.build_venv/bin/python -m grpc_tools.protoc -I$(PROTO_DIR) \
		--python_out=. --grpc_python_out=. $(PROTO_DIR)/scanner.proto
	rm -rf .build_venv

check-deps:
	@echo "--- Checking Dependencies ---"
	@python3 -c "import grpc" 2>/dev/null || (echo "Missing grpcio. (Arch: python-grpcio)" && exit 1)
	@python3 -c "import pyudev" 2>/dev/null || (echo "Missing pyudev. (Arch: python-pyudev)" && exit 1)
	@python3 -c "import watchdog" 2>/dev/null || (echo "Missing watchdog. (Arch: python-watchdog)" && exit 1)
	@python3 -c "import tkinter" 2>/dev/null || (echo "Missing tk. (Arch: tk)" && exit 1)

cert-sync:
	@if [ -f $(SERVER_DIR)/$(CERT_FILE) ]; then \
		cp $(SERVER_DIR)/$(CERT_FILE) .; \
		echo "Synced SSL certificate from server."; \
	else \
		echo "Warning: No server certificate found at $(SERVER_DIR). Running in insecure mode."; \
	fi

install: check-deps cert-sync
	@echo "--- Installing Files ---"
	install -d $(OPT_DIR)
	install -d $(CERT_DIR)
	install -d /run/usb_scanner
	chmod 777 /run/usb_scanner
	
	# Install scripts
	install -m 755 usb_guard.py usb_resolver.py watcher.py $(OPT_DIR)/
	install -m 644 ../../scanner_client.py scanner_pb2.py scanner_pb2_grpc.py $(OPT_DIR)/

	# Install Certificates (600 for key, 644 for crt)
	@if [ -f "$(CERT_FILE)" ]; then \
		install -m 644 $(CERT_FILE) $(CERT_DIR)/; \
		echo "Installed $(CERT_FILE)"; \
	fi
	@if [ -f "dev_server.key" ]; then \
		install -m 600 dev_server.key $(CERT_DIR)/; \
		echo "Installed dev_server.key"; \
	fi

	@echo "--- Installing Services ---"
	install -m 644 usb_guard.service $(SYSTEMD_ROOT)/
	install -d $(SYSTEMD_USER)
	install -m 644 usb_watcher.service $(SYSTEMD_USER)/
	
	systemctl daemon-reload
	@echo "Done. Services installed. Ensure cert paths in usb_guard match $(CERT_DIR)/"

uninstall:
	-systemctl stop usb_guard
	-systemctl --user stop usb_watcher
	rm -rf $(OPT_DIR)
	rm -f $(SYSTEMD_ROOT)/usb_guard.service
	rm -f $(SYSTEMD_USER)/usb_watcher.service
	systemctl daemon-reload
	@echo "Uninstallation complete."

tail:
	journalctl -u usb_guard -f
