import grpc
import os
import enum
from datetime import datetime
import scanner_pb2
import scanner_pb2_grpc

# Configuration
CHUNK_SIZE = 64 * 1024
MAX_FILE_SCAN_SIZE = 24 * 1024 * 1024  # 24MB Cap to prevent Broken Pipe

class LogLevel(enum.IntEnum):
    BAD_ONLY = 1
    ALL = 2

class _LogLevel(enum.IntEnum):
    INFO = 1
    INFECTED = 2
    ERROR = 3

class ScannerClient:
    def __init__(self, server_address="localhost:50051", logger=None, log_level=LogLevel.BAD_ONLY, cert_path=None):
        self.server_address = server_address
        self.logger = logger
        self.log_level = log_level

        if cert_path:
            if os.path.exists(cert_path):
                with open(cert_path, 'rb') as f:
                    creds = grpc.ssl_channel_credentials(f.read())
                # Use secure_channel
                self.channel = grpc.secure_channel(server_address, creds)
                self.logger.info("Encrypted TLS channel initialized.")
            else:
                # CRITICAL: Don't fall back to insecure if a cert was explicitly requested!
                raise FileNotFoundError(f"SSL Certificate not found at: {cert_path}")
        else:
            self.channel = grpc.insecure_channel(server_address)
            self.logger.warning("Using insecure gRPC channel!")

    def _log(self, message, event_level):
        """
        Decides whether to log based on the user's LogLevel preference,
        then routes to the professional logger or print fallback.
        """
        # 1. Filter Logic: If BAD_ONLY, skip INFO events
        if self.log_level == LogLevel.BAD_ONLY and event_level == _LogLevel.INFO:
            return

        # 2. Routing Logic
        if self.logger:
            # Map our internal _LogLevel to the standard logging framework methods
            if event_level == _LogLevel.INFO:
                self.logger.info(message)
            elif event_level == _LogLevel.INFECTED:
                # We use warning or critical for infections
                self.logger.warning(f"{message}")
            elif event_level == _LogLevel.ERROR:
                self.logger.error(f"{message}")
        else:
            # Fallback to print if no logger is provided
            print(f"[{event_level.name}] {message}")

    def is_server_alive(self, timeout=3):
        """Checks if the gRPC server is responding."""
        try:
            # Attempts to connect to the channel within the timeout
            grpc.channel_ready_future(self.channel).result(timeout=timeout)
            return True
        except (grpc.FutureTimeoutError, Exception) as e:
            self.logger.error(f"Heartbeat failed for {self.server_address}: {e}")
            return False

    def _file_generator(self, directory_path):
        for root, _, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, directory_path)
                bytes_sent = 0
                try:
                    with open(full_path, "rb") as f:
                        while bytes_sent < MAX_FILE_SCAN_SIZE:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk: break
                            yield scanner_pb2.ScanRequest(
                                path_within_directory=rel_path,
                                chunk_data=chunk,
                                end_of_file=False
                            )
                            bytes_sent += len(chunk)

                    yield scanner_pb2.ScanRequest(
                        path_within_directory=rel_path,
                        chunk_data=b"",
                        end_of_file=True
                    )
                except Exception as e:
                    self._log(f"Error reading {rel_path}: {e}", _LogLevel.ERROR)

    def scan_directory(self, path):
        infected_files = []
        try:
            stub = scanner_pb2_grpc.FileServiceStub(self.channel)
            # We wrap the call in a try-except to catch the Broken Pipe/gRPC errors
            responses = stub.ScanDirectory(self._file_generator(path))

            for response in responses:
                status = response.status.upper()
                output = f"[{status}] {response.path_within_directory}"

                if "INFECTED" in status:
                    infected_files.append(response.path_within_directory)
                    self._log(f"{output}", _LogLevel.INFECTED)
                elif "CLEAN" in status:
                    self._log(f"{output}", _LogLevel.INFO)
                elif "ERROR" in status:
                    self._log(f"{output}", _LogLevel.ERROR)

        except Exception as e:
            self._log(f"Connection or Stream Error: {e}", _LogLevel.ERROR)

        return infected_files

