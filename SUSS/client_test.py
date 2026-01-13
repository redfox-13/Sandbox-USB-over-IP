import grpc
import os
import scanner_pb2
import scanner_pb2_grpc

CHUNK_SIZE = 64 * 1024

class ScannerClient:
    def __init__(self, server_address="localhost:50051"):
        self.server_address = server_address

    def _file_generator(self, directory_path):
        """Walks directory and yields gRPC ScanRequests"""
        for root, _, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, directory_path)
                
                try:
                    with open(full_path, "rb") as f:
                        while True:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk: break
                            yield scanner_pb2.ScanRequest(
                                path_within_directory=rel_path,
                                chunk_data=chunk,
                                end_of_file=False
                            )
                    # End of this specific file
                    yield scanner_pb2.ScanRequest(
                        path_within_directory=rel_path,
                        end_of_file=True
                    )
                except Exception as e:
                    print(f"Error reading {rel_path}: {e}")

    def scan_directory(self, path):
        """Main entry point for the Service Provider"""
        with grpc.insecure_channel(self.server_address) as channel:
            stub = scanner_pb2_grpc.FileServiceStub(channel)
            responses = stub.ScanDirectory(self._file_generator(path))
            
            results = []
            for response in responses:
                print(f"[{response.status}] {response.path_within_directory}")
                results.append(response)
            return results