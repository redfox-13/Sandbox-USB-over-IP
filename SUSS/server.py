import grpc
import socket
import docker
import time
import logging
from concurrent import futures
from datetime import datetime
import scanner_pb2
import scanner_pb2_grpc

# Configure logging with timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('scanner_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FileScannerServicer(scanner_pb2_grpc.FileServiceServicer):
    def __init__(self):
        logger.info("Initializing FileScannerServicer...")
        self.docker_client = docker.from_env()
        logger.info("Docker client initialized successfully")

    def _wait_for_clamav(self, ip, port=3310, timeout=60):
        """Polls the container until ClamAV database is loaded."""
        logger.info(f"Waiting for ClamAV to be ready on {ip}:{port} (timeout: {timeout}s)")
        start_time = time.time()
        attempt = 0
        while time.time() - start_time < timeout:
            attempt += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, port))
                    s.send(b"PING\0")
                    response = s.recv(1024)
                    if b"PONG" in response:
                        elapsed = time.time() - start_time
                        logger.info(f"ClamAV is ready after {elapsed:.2f}s (attempt {attempt})")
                        return True
            except Exception as e:
                logger.debug(f"ClamAV not ready yet (attempt {attempt}): {e}")
            time.sleep(2)
        logger.error(f"ClamAV initialization timed out after {timeout}s")
        return False

    def _scan_single_file(self, host, port, first_request, request_iterator):
        """Helper to process one file's worth of chunks from the stream."""
        file_path = first_request.path_within_directory
        logger.info(f"Starting scan for: {file_path}")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            logger.debug(f"Connecting to ClamAV at {host}:{port}")
            client.connect((host, port))
            client.send(b"zINSTREAM\0")
            logger.debug(f"Sent INSTREAM command for {file_path}")

            chunk_count = 0
            total_bytes = 0

            # 1. Process the first chunk already pulled from the iterator
            if first_request.chunk_data:
                chunk_count += 1
                chunk_size = len(first_request.chunk_data)
                total_bytes += chunk_size
                size = len(first_request.chunk_data).to_bytes(4, 'big')
                client.send(size + first_request.chunk_data)
                logger.debug(f"Sent chunk {chunk_count} ({chunk_size} bytes) for {file_path}")
            
            if first_request.end_of_file:
                # File was only one chunk long
                logger.debug(f"File {file_path} is single chunk")
                pass
            else:
                # 2. Pull remaining chunks for THIS file only from the iterator
                for req in request_iterator:
                    if req.chunk_data:
                        chunk_count += 1
                        chunk_size = len(req.chunk_data)
                        total_bytes += chunk_size
                        size = len(req.chunk_data).to_bytes(4, 'big')
                        client.send(size + req.chunk_data)
                        logger.debug(f"Sent chunk {chunk_count} ({chunk_size} bytes) for {file_path}")
                    if req.end_of_file:
                        break

            # 3. Terminate stream and get result
            logger.debug(f"Terminating stream for {file_path} (sent {chunk_count} chunks, {total_bytes} bytes total)")
            client.send((0).to_bytes(4, 'big'))
            response = client.recv(1024).decode('utf-8').strip()
            
            result = "CLEAN" if "OK" in response else f"INFECTED: {response}"
            logger.info(f"Scan result for {file_path}: {result}")
            return result
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}", exc_info=True)
            return f"ERROR: {str(e)}"
        finally:
            client.close()

    def ScanDirectory(self, request_iterator, context):
        logger.info("=" * 80)
        logger.info("NEW USB SCAN SESSION STARTED")
        logger.info("=" * 80)
        container = None
        ip = None
        host_port = None

        try:
            # 1. Start Container
            logger.info("Starting Docker container for ClamAV scanning...")
            container = self.docker_client.containers.run(
                image="fast-clamav:latest",
                detach=True,
                mem_limit="2g",
                remove=True,
                ports={"3310/tcp": None}
            )
            logger.info(f"Container started with ID: {container.id[:12]}")

            container.reload()
            logger.debug("Container reloaded, retrieving port mapping...")

            port_info = container.attrs["NetworkSettings"]["Ports"]["3310/tcp"]
            if not port_info:
                raise Exception("ClamAV port not published")

            host_port = int(port_info[0]["HostPort"])
            logger.info(f"ClamAV service mapped to host port: {host_port}")

            # 2. Wait for ClamAV DB to load
            logger.info("Waiting for ClamAV database to load...")
            if not self._wait_for_clamav("127.0.0.1", host_port):
                raise Exception("ClamAV initialization timed out")

            logger.info("ClamAV is ready. Beginning file scanning...")
            logger.info("-" * 80)

            # 3. Main Stream Loop
            file_count = 0
            for request in request_iterator:
                file_count += 1
                result_status = self._scan_single_file(
                    "127.0.0.1",
                    host_port,
                    request,
                    request_iterator
                )
                
                logger.debug(f"Yielding result for {request.path_within_directory}")
                yield scanner_pb2.ScanResult(
                    path_within_directory=request.path_within_directory,
                    status=result_status
                )

            logger.info("-" * 80)
            logger.info(f"Scanning completed. Total files processed: {file_count}")

        except Exception as e:
            logger.error(f"Session Error: {e}", exc_info=True)
            yield scanner_pb2.ScanResult(
                path_within_directory="",
                status=f"ERROR: {str(e)}"
            )
        finally:
            if container:
                logger.info("Stopping Docker container...")
                try:
                    container.stop()
                    logger.info("Container stopped successfully")
                except Exception as e:
                    logger.warning(f"Error stopping container: {e}")
            logger.info("=" * 80)
            logger.info("USB SCAN SESSION ENDED")
            logger.info("=" * 80)

def serve():
    logger.info("Initializing gRPC server...")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    scanner_pb2_grpc.add_FileServiceServicer_to_server(FileScannerServicer(), server)
    server.add_insecure_port('[::]:50051')
    logger.info("=" * 80)
    logger.info("gRPC Scanner Server is running on port 50051")
    logger.info("Waiting for client connections...")
    logger.info("=" * 80)
    server.start()
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Stopping server...")
        server.stop(0)

if __name__ == "__main__":
    serve()
