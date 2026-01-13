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

    def _wait_for_clamav(self, ip, port=3310, timeout=60):
        """Polls the container until ClamAV database is loaded."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, port))
                    s.send(b"PING\0")
                    if b"PONG" in s.recv(1024):
                        return True
            except (socket.error, ConnectionResetError):
                pass
            time.sleep(2)
        return False

    def _scan_single_file(self, host, port, first_request, request_iterator):
        """Helper to process one file's worth of chunks from the stream."""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((host, port))
            client.send(b"zINSTREAM\0")

            # 1. Process the first chunk already pulled from the iterator
            if first_request.chunk_data:
                size = len(first_request.chunk_data).to_bytes(4, 'big')
                client.send(size + first_request.chunk_data)
            
            if first_request.end_of_file:
                # File was only one chunk long
                pass
            else:
                # 2. Pull remaining chunks for THIS file only from the iterator
                for req in request_iterator:
                    if req.chunk_data:
                        size = len(req.chunk_data).to_bytes(4, 'big')
                        client.send(size + req.chunk_data)
                    if req.end_of_file:
                        break

            # 3. Terminate stream and get result
            client.send((0).to_bytes(4, 'big'))
            response = client.recv(1024).decode('utf-8').strip()
            return "CLEAN" if "OK" in response else f"INFECTED: {response}"
        finally:
            client.close()

    def ScanDirectory(self, request_iterator, context):
        print("--- New USB Session Started ---")
        container = None
        ip = None

        try:
            # 1. Start Container
            container = self.docker_client.containers.run(
                image="fast-clamav:latest",
                detach=True,
                mem_limit="2g",
                remove=True,
                ports={"3310/tcp": None}
            )

            """ # 2. Get IP (with retry)
            for _ in range(10):
                container.reload()
                networks = container.attrs['NetworkSettings']['Networks']
                if networks:
                    ip = list(networks.values())[0].get('IPAddress')
                    if ip: break
                time.sleep(1)

            if not ip:
                raise Exception("Could not assign IP to container") """
            
            container.reload()

            port_info = container.attrs["NetworkSettings"]["Ports"]["3310/tcp"]
            if not port_info:
                raise Exception("ClamAV port not published")

            host_port = int(port_info[0]["HostPort"])


            # 3. Wait for ClamAV DB to load
            print(f"Container {ip} started. Waiting for ClamAV...")
            if not self._wait_for_clamav("127.0.0.1", host_port):
                raise Exception("ClamAV initialization timed out")


            # 4. Main Stream Loop
            # We manually call next() so we can pass control to the helper
            for request in request_iterator:
                result_status = self._scan_single_file(
                    "127.0.0.1",
                    host_port,
                    request,
                    request_iterator
                )
                
                yield scanner_pb2.ScanResult(
                    path_within_directory=request.path_within_directory,
                    status=result_status
                )

        except Exception as e:
            print(f"Session Error: {e}")
        finally:
            if container:
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
