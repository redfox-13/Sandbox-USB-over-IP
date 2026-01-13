import grpc
import socket
import docker
import time
from concurrent import futures
import scanner_pb2
import scanner_pb2_grpc

class FileScannerServicer(scanner_pb2_grpc.FileServiceServicer):
    def __init__(self):
        self.docker_client = docker.from_env()

    def _get_scan_result(self, ip, request_iterator, first_request):
        """Helper to pipe chunks into the clamd socket"""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((ip, 3310))
            client.send(b"zINSTREAM\0")

            # Process the very first chunk we already received
            if first_request.chunk_data:
                size = len(first_request.chunk_data).to_bytes(4, 'big')
                client.send(size + first_request.chunk_data)

            # Continue pulling from the stream until end_of_file
            for req in request_iterator:
                if req.chunk_data:
                    size = len(req.chunk_data).to_bytes(4, 'big')
                    client.send(size + req.chunk_data)
                
                if req.end_of_file:
                    break

            # Terminate ClamAV stream (0-length chunk)
            client.send((0).to_bytes(4, 'big'))
            
            response = client.recv(1024).decode('utf-8').strip()
            return "CLEAN" if "OK" in response else f"INFECTED: {response}"
        finally:
            client.close()

    def ScanDirectory(self, request_iterator, context):
        print("--- New USB Session Started ---")
        
        # 1. Spin up the dedicated scanner container
        container = self.docker_client.containers.run(
            image="fast-clamav:latest",
            detach=True,
            mem_limit="2g",  # Safety cap for host RAM
            remove=True      # Auto-cleanup on stop
        )
        
        try:
            # Wait for clamd to boot up (usually 5-10 seconds)
            # In a production app, you'd poll the socket instead of sleep
            time.sleep(10) 
            # Reload to ensure attributes are populated
            container.reload()

            # Option A: The most common path for default Docker bridge
            networks = container.attrs['NetworkSettings']['Networks']
            if 'bridge' in networks:
                ip = networks['bridge']['IPAddress']
            else:
                # Option B: Fallback for custom networks (gets the first one available)
                ip = list(networks.values())[0]['IPAddress']

            print(f"Scanner container ready at {ip}")
            # 2. Iterate through the stream of files
            for request in request_iterator:
                # Every time a new file starts, we call our socket helper
                # We pass the current request and the iterator
                result_status = self._get_scan_result(ip, request_iterator, request)
                
                yield scanner_pb2.ScanResult(
                    path_within_directory=request.path_within_directory,
                    status=result_status
                )

        except Exception as e:
            print(f"Session Error: {e}")
        finally:
            print("--- Closing Session. Stopping Container ---")
            container.stop()

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    scanner_pb2_grpc.add_FileServiceServicer_to_server(FileScannerServicer(), server)
    server.add_insecure_port('[::]:50051')
    print("gRPC Server running on port 50051...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
