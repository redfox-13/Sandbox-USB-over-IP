# --- SERVER MAKEFILE ---
VENV = .svenv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
PROTO_DIR = ../proto
DEV_CERT = dev_server.crt
DEV_KEY = dev_server.key

.PHONY: all configure certs clean

all: configure certs
	@echo "Server ready. Run 'python3 server.py' to start."

configure:
	@echo "--- Building gRPC Stubs ---"
	python3 -m venv .build_venv
	.build_venv/bin/pip install grpcio-tools protobuf > /dev/null
	.build_venv/bin/python -m grpc_tools.protoc -I$(PROTO_DIR) \
		--python_out=. --grpc_python_out=. $(PROTO_DIR)/scanner.proto

certs-out:
	@if [ ! -f $(DEV_CERT) ]; then \
		echo "Generating Dev SSL Certificates for other machines..."; \
		openssl req -x509 -newkey rsa:4096 -keyout $(DEV_KEY) -out $(DEV_CERT) -days 365 -nodes -config openssl.conf -extensions v3_req; \
	fi

certs:
	@if [ ! -f $(DEV_CERT) ]; then \
		echo "Generating Dev SSL Certificates..."; \
		openssl req -x509 -newkey rsa:4096 -keyout $(DEV_KEY) -out $(DEV_CERT) -days 365 -nodes -subj "/CN=localhost"; \
	fi

clean:
	rm -rf $(VENV)
	rm -rf .build_venv
	rm -f *_pb2*.py $(DEV_CERT) $(DEV_KEY)
	@echo "Cleanup complete."

run: venv certs
	$(PYTHON) server.py

venv: $(VENV)/bin/activate

$(VENV)/bin/activate: requirements.txt
	@echo "Creating virtual environment..."
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	@echo "Installing dependencies from requirements.txt..."
	$(PIP) install -r requirements.txt
	@echo "Generating gRPC stubs..."
	$(PYTHON) -m grpc_tools.protoc -I$(PROTO_DIR) \
		--python_out=. --grpc_python_out=. $(PROTO_DIR)/scanner.proto
	@echo "Run '. $(VENV)/bin/activate' to activate the environment"
