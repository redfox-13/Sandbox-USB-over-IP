import grpc
import socket
import docker
import time
from concurrent import futures
import scanner_pb2
import scanner_pb2_grpc
from datetime import datetime

def get_timestamp():
    """Returns ISO 8601 timestamp with millisecond precision."""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

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
                    s.sendall(b"PING\0")
                    if b"PONG" in s.recv(1024):
                        return True
            except:
                pass
            time.sleep(2)
        return False

    def _scan_file_logic(self, ip, first_request, request_iterator):
        """Processes one file's worth of data over the ClamAV socket."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clamd:
                clamd.settimeout(15)
                clamd.connect((ip, 3310))
                clamd.sendall(b"zINSTREAM\0")

                # Send the first chunk
                data = first_request.chunk_data or b""
                size = len(data).to_bytes(4, 'big')
                clamd.sendall(size + data)

                # Pull more chunks from the stream if the file isn't finished
                if not first_request.end_of_file:
                    for sub_req in request_iterator:
                        sub_data = sub_req.chunk_data or b""
                        clamd.sendall(len(sub_data).to_bytes(4, 'big') + sub_data)
                        if sub_req.end_of_file:
                            # Update path for the return result
                            first_request.path_within_directory = sub_req.path_within_directory
                            break

                # Protocol terminator (Zero-size chunk)
                clamd.sendall((0).to_bytes(4, 'big'))

                # Get response
                response = clamd.recv(1024).decode('utf-8').strip()
                if not response:
                    return "ERROR: No response"
                return "CLEAN" if "OK" in response else f"INFECTED: {response}"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def ScanDirectory(self, request_iterator, context):
            print(f"[{get_timestamp()}] --- New USB Session Started ---")
            container = None
            ip = None

            try:
                # 1. Start the Scanner Container
                container = self.docker_client.containers.run(
                    image="fast-clamav:latest", detach=True, mem_limit="2g", remove=True
                )

                # 2. Get IP & Wait for DB
                for _ in range(10):
                    container.reload()
                    nets = container.attrs['NetworkSettings']['Networks']
                    if nets:
                        ip = list(nets.values())[0].get('IPAddress')
                        if ip: break
                    time.sleep(1)

                if not ip or not self._wait_for_clamav(ip):
                    raise Exception("ClamAV failed to start")

                # 3. THE FIX: Controlled Iterator Loop
                while True:
                    try:
                        # Manually pull the first chunk of a file
                        request = next(request_iterator)
                    except StopIteration:
                        # Normal end of the USB partition scan
                        break 

                    status = "UNKNOWN"
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clamd:
                        try:
                            clamd.settimeout(15)
                            clamd.connect((ip, 3310))
                            clamd.sendall(b"zINSTREAM\0")

                            # Send the chunk we just pulled with next()
                            data = request.chunk_data or b""
                            clamd.sendall(len(data).to_bytes(4, 'big') + data)

                            # If the file has more chunks, consume them
                            if not request.end_of_file:
                                for sub_req in request_iterator:
                                    sub_data = sub_req.chunk_data or b""
                                    clamd.sendall(len(sub_data).to_bytes(4, 'big') + sub_data)
                                    if sub_req.end_of_file:
                                        request = sub_req # Update for the yield
                                        break
                            
                            # Close ClamAV stream for this file
                            clamd.sendall((0).to_bytes(4, 'big'))
                            raw_res = clamd.recv(1024).decode('utf-8').strip()
                            status = "CLEAN" if "OK" in raw_res else f"INFECTED: {raw_res}"
                            
                        except Exception as e:
                            status = f"ERROR: Socket failure ({e})"

                    yield scanner_pb2.ScanResult(
                        path_within_directory=request.path_within_directory,
                        status=status
                    )

            except Exception as e:
                print(f"[{get_timestamp()}] Session Error: {e}")
            finally:
                if container:
                    print(f"[{get_timestamp()}] --- Stopping Container ---")
                    container.stop()
def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    scanner_pb2_grpc.add_FileServiceServicer_to_server(FileScannerServicer(), server)
    server.add_insecure_port('[::]:50051')
    print("Server active on port 50051...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
