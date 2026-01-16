import grpc
import os
import enum
from datetime import datetime # <--- CRITICAL IMPORT
import scanner_pb2
import scanner_pb2_grpc

# Configuration
CHUNK_SIZE = 64 * 1024
MAX_FILE_SCAN_SIZE = 24 * 1024 * 1024  # 24MB Cap to prevent Broken Pipe

def get_timestamp():
    """Returns ISO 8601 timestamp with millisecond precision."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

class LogLevel(enum.IntEnum):
    DEBUG = 1
    INFO = 2
    WARN = 3

class ScannerClient:
    def __init__(self, server_address="localhost:50051", log_level=LogLevel.WARN):
        self.server_address = server_address
        self.log_level = log_level

    def _log(self, message, message_level):
        """Uses the get_timestamp function defined above."""
        if message_level >= self.log_level:
            print(f"[{get_timestamp()}] {message}")

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
                    self._log(f"DEBUG: Error reading {rel_path}: {e}", LogLevel.DEBUG)

    def scan_directory(self, path):
        infected_files = []
        try:
            with grpc.insecure_channel(self.server_address) as channel:
                stub = scanner_pb2_grpc.FileServiceStub(channel)
                # We wrap the call in a try-except to catch the Broken Pipe/gRPC errors
                responses = stub.ScanDirectory(self._file_generator(path))
                
                for response in responses:
                    status = response.status.upper()
                    output = f"[{status}] {response.path_within_directory}"

                    if "INFECTED" in status:
                        infected_files.append(response.path_within_directory)
                        self._log(f"🚨 {output}", LogLevel.WARN)
                    elif "CLEAN" in status:
                        self._log(f"✅ {output}", LogLevel.INFO)
                    elif "ERROR" in status:
                        self._log(f"⚠️ {output}", LogLevel.DEBUG)
                        
        except Exception as e:
            self._log(f"DEBUG: Connection or Stream Error: {e}", LogLevel.DEBUG)
            
        return infected_files

