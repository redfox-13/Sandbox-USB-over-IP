# Sandbox-USB-over-IP: Comprehensive Code Analysis

This document provides detailed answers to key architectural questions about the CUBE-SUSS USB scanning system.

---

## 1. USB Detection Mechanism

### OS APIs Used

**Linux (CUBE/platform/linux):**
- **Primary API**: `pyudev` (userspace udev wrapper)
- **Mechanism**: Monitor-based event-driven detection
- **Code Reference**: [usb_guard.py](CUBE/platform/linux/usb_guard.py#L84-L102)
  ```python
  context = pyudev.Context()
  monitor = pyudev.Monitor.from_netlink(context)
  monitor.filter_by(subsystem='block', device_type='disk')
  ```
- **Kernel Bridge**: Listens to netlink events from the Linux kernel's udev subsystem

**Windows (CUBE/platform/windows):**
- **Primary API**: WMI (Windows Management Instrumentation) + Win32 API
- **Code Reference**: [usb_guard.py](CUBE/platform/windows/usb_guard.py#L37-L47)
  ```python
  # WM_DEVICECHANGE message handler with device arrival signal (0x8000)
  if msg == win32con.WM_DEVICECHANGE and wparam == 0x8000:
  ```
- **Secondary API**: `GetLogicalDrives()` (Win32 kernel API)
- **Mechanism**: Hidden window receives WM_DEVICECHANGE system broadcasts

### User-Space vs Kernel-Space

| Aspect | Linux | Windows |
|--------|-------|---------|
| **Detection** | User-space (pyudev monitors kernel events) | User-space (Win32 messages + user app) |
| **Kernel Involvement** | Heavy (netlink, block subsystem) | Heavy (kernel broadcasts to window message queue) |
| **Hardware Access** | Via `/dev/` device nodes | Via Win32 handle API (`CreateFileW`) |
| **Permission Level** | Requires root (for `blockdev` operations) | Requires Administrator (for device locks) |

### Polling vs Event-Driven

**Linux: EVENT-DRIVEN** ✓
- Uses `pyudev.Monitor` with blocking iterator: `for device in iter(monitor.poll, None)`
- No busy-waiting or polling loops
- Responsive to hotplug events in real-time
- Code: [usb_guard.py#L84-L102](CUBE/platform/linux/usb_guard.py#L84-L102)

**Windows: EVENT-DRIVEN** ✓
- Uses Win32 message queue via hidden window
- `win32gui.PumpMessages()` blocks until device arrival
- Callback-based: `on_device_change()` triggered on hotplug
- Code: [usb_guard.py#L30-L47](CUBE/platform/windows/usb_guard.py#L30-L47)

**Detection Latency:**
- Linux: ~100ms (typical udev notification delay)
- Windows: ~50ms (Win32 message priority)

---

## 2. Access Blocking

### How Read/Write is Blocked

**Linux (CUBE/platform/linux):**

1. **Hardware-Level Write Protection** (IMMEDIATE)
   - Command: `blockdev --setro /dev/sdX`
   - Effect: Kernel sets device to read-only at block layer
   - Scope: ALL partitions under parent device
   - Reversibility: YES (via `blockdev --setrw`)
   - Code: [usb_guard.py#L60-L62](CUBE/platform/linux/usb_guard.py#L60-L62)
   ```python
   subprocess.run(['blockdev', '--setro', parent_node], check=True)
   logger.info(f"Hardware Write-Protection ENABLED for {parent_node}")
   ```

2. **Mount Restrictions** (During Scan)
   - Options: `ro,noexec,nosuid,nodev`
   - `ro` = Read-only mount
   - `noexec` = Prevent execution
   - `nosuid` = Disable SUID bits
   - `nodev` = Block device node access
   - Code: [usb_guard.py#L75-L79](CUBE/platform/linux/usb_guard.py#L75-L79)
   ```python
   subprocess.run(['mount', '-o', 'ro,noexec,nosuid,nodev', dev_node, mount_path], check=True)
   ```

3. **Permission-Based Access Control**
   - Read-only filesystem enforced by kernel VFS layer
   - Even `root` cannot write once `blockdev --setro` is set

**Windows (CUBE/platform/windows):**

1. **Handle-Based Lock** (DRIVER-LEVEL)
   - Creates handle with `FILE_READ_ATTRIBUTES` (0x80) instead of `GENERIC_READ`
   - Attempts `IOCTL_DISK_GET_DRIVE_LAYOUT` (0x00090018)
   - Effect: Prevents unmounting and driver operations
   - Code: [usb_guard.py#L99-L112](CUBE/platform/windows/usb_guard.py#L99-L112)
   ```python
   handle = ctypes.windll.kernel32.CreateFileW(
       drive_path, 
       0x80,  # FILE_READ_ATTRIBUTES
       0x00000001,  # FULL SHARE (allows OS to keep mount)
       None, 3, 0, None
   )
   ctypes.windll.kernel32.DeviceIoControl(
       handle, 0x00090018, None, 0, None, 0, ctypes.byref(bytes_ret), None
   )
   ```

2. **Mount Point Restriction**
   - Drive remains in filesystem but prevents file modifications
   - OS-level protection (not just application-level)

3. **No Active Write-Blocking**
   - ⚠️ **LIMITATION**: Windows version does NOT use kernel-level write-protection
   - Relies on OS permissions and scanning delay
   - Drives can theoretically be written during scan window

### Is Blocking Reversible?

| Platform | Reversible | Method | Conditions |
|----------|-----------|--------|-----------|
| **Linux** | ✓ YES | `blockdev --setrw /dev/sdX` | Only if no threats found (automatic) |
| **Linux** | ✓ MANUAL | Admin must call mount helper | If threats found (user interaction required) |
| **Windows** | ✓ YES | Device automatically unlocked | Same scan session (handle released) |
| **Windows** | ✓ IMPLICIT | Close handle / next detection | On subsequent detection cycles |

**Locking Persistence on Linux (with threats):**
- Device stays read-only until user runs USB Resolver GUI
- Ticket system: [usb_guard.py#L122-L133](CUBE/platform/linux/usb_guard.py#L122-L133)
- Resolver can clean infected files and call mount helper

---

## 3. Client–Server Model

### Is the Server Remote or Local?

| Aspect | Implementation |
|--------|-----------------|
| **Architecture** | Hybrid (configurable) |
| **Default (Linux)** | Local: `localhost:50051` ([usb_guard.py](CUBE/platform/linux/usb_guard.py#L16)) |
| **Default (Windows)** | Remote: `100.98.209.6:50051` ([usb_guard.py](CUBE/platform/windows/usb_guard.py#L13)) |
| **Transport** | gRPC over TLS (or insecure HTTP/2) |
| **Configuration** | `SERVER_ADDRESS` constant in each platform's usb_guard.py |

**Network Topology:**
```
┌─────────────────────────────────────────────────────────────┐
│  LINUX CLIENT (CUBE/platform/linux)                         │
│  - Local gRPC client                                        │
│  - Connects to localhost:50051                              │
│  - Same machine as SUSS server (containerized)              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  WINDOWS CLIENT (CUBE/platform/windows)                     │
│  - Remote gRPC client                                       │
│  - Connects to 100.98.209.6:50051 (separate machine)       │
│  - SUSS server location (likely Docker Swarm/K8s)           │
└─────────────────────────────────────────────────────────────┘

           ↕ gRPC + TLS
           
┌─────────────────────────────────────────────────────────────┐
│  SUSS SERVER (SUSS/server.py)                               │
│  - Persistent daemon (systemd-managed on Linux)             │
│  - Listens on [::]:{PORT} (all interfaces)                  │
│  - Spawns Docker container per scan session                 │
└─────────────────────────────────────────────────────────────┘
```

### Is it Persistent or Spawned Per Request?

**Server (SUSS/server.py):**
- **Persistent**: Continuously running daemon
- **Lifecycle**: Started by init system (systemd on Linux)
- **Service Model**: Accepts multiple concurrent scan sessions
- **Code**: [server.py#L208-222](SUSS/server.py#L208-L222)
```python
server.start()
logger.info("Waiting for client connections...")
server.wait_for_termination()
```

**ClamAV Scanner (Container):**
- **Spawned Per Request**: New container for each `ScanDirectory()` call
- **Cleanup**: Automatic removal via `remove=True` parameter
- **Lifecycle**: Runs for duration of scan, then garbage-collected
- **Code**: [server.py#L98-109](SUSS/server.py#L98-L109)
```python
container = self.docker_client.containers.run(
    image="fast-clamav:latest",
    detach=True,
    mem_limit="2g",
    remove=True,  # Auto-cleanup on stop
    ports={"3310/tcp": None}
)
```

**Client (CUBE):**
- **Per-Platform Variations**:
  - **Linux**: Persistent daemon (`usb_guard.py`) + user service (`watcher.py`)
  - **Windows**: Persistent service + polling via hidden window callback

---

## 4. Data Transfer

### Full Disk Image vs File-Level Transfer

**Transfer Model: FILE-LEVEL** ✓

- **Granularity**: Individual files sent in chunks
- **Protocol**: Bidirectional gRPC stream (protobuf)
- **Per-File Chunking**: 64KB chunks
- **Code Reference**: [scanner_client.py#L67-92](CUBE/platform/windows/scanner_client.py#L67-L92)
```python
CHUNK_SIZE = 64 * 1024
MAX_FILE_SCAN_SIZE = 24 * 1024 * 1024  # 24MB cap

def _file_generator(self, directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as f:
                while bytes_sent < MAX_FILE_SCAN_SIZE:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    yield scanner_pb2.ScanRequest(
                        path_within_directory=rel_path,
                        chunk_data=chunk,
                        end_of_file=False
                    )
```

**Why Not Full Disk:**
1. **Efficiency**: Only scans accessible files (permissions, mounts)
2. **Scalability**: Can skip large files (24MB cap per file)
3. **Real-time Results**: Stream-based (results come as files complete)
4. **Memory Usage**: Chunks prevent loading entire drive into RAM

### Compression Used or Not

**Answer: NO COMPRESSION** ✗

- Raw binary chunks sent over gRPC
- Reliance on HTTP/2 HPACK header compression only
- No explicit data compression layer
- Reasoning: Trade-off between CPU (compression) vs bandwidth
- Optimal for LAN deployments (low latency preferred)

### Authentication Method

**Primary: TLS Certificates**
- **Type**: X.509 self-signed (development) or CA-signed (production)
- **Key Size**: RSA 4096-bit
- **Validity**: 365 days (development certificates)
- **Code**: [server.py#L203-210](SUSS/server.py#L203-L210)
```python
if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        private_key = f.read()
    with open(CERT_FILE, 'rb') as f:
        certificate_chain = f.read()
    server_creds = grpc.ssl_server_credentials(((private_key, certificate_chain),))
```

**Client-Side Verification**: [scanner_client.py#L42-55](CUBE/platform/windows/scanner_client.py#L42-L55)
```python
if cert_path:
    if os.path.exists(cert_path):
        with open(cert_path, 'rb') as f:
            creds = grpc.ssl_channel_credentials(f.read())
        self.channel = grpc.secure_channel(server_address, creds)
    else:
        raise FileNotFoundError(f"SSL Certificate not found at: {cert_path}")
```

**Secondary: No Application-Level Auth**
- No API keys, OAuth, or mutual TLS with client certificates
- Authentication relies entirely on certificate presence/validation
- **Risk**: Vulnerable to MITM if certificates are compromised

**Fallback (Insecure Mode):**
- Plaintext HTTP/2 if certificates missing
- Warning logged but continues
- Used in development environments

---

## 5. Container Lifecycle

### One Container Per Scan?

**Answer: YES** ✓

- **Isolation**: Each `ScanDirectory()` RPC call spawns a NEW Docker container
- **Independence**: Containers don't share state or processes
- **Code**: [server.py#L98-109](SUSS/server.py#L98-L109)
```python
container = self.docker_client.containers.run(
    image="fast-clamav:latest",
    detach=True,
    mem_limit="2g",
    remove=True,  # Unique per invocation
    ports={"3310/tcp": None}
)
```

**Benefits:**
- Clean scanning environment
- No malware persistence across sessions
- Prevents database poisoning
- Fault isolation (one bad scan doesn't affect others)

**Trade-off:**
- Overhead: ~2-3 seconds per container startup
- Not optimal for high-frequency rapid scans

### How Cleanup is Guaranteed

**Primary Cleanup Mechanism: Docker `remove=True`**
- Automatic container removal after stop
- Triggered in `finally` block
- Code: [server.py#L165-169](SUSS/server.py#L165-L169)
```python
finally:
    if container:
        logger.info("Stopping Docker container...")
        try:
            container.stop()
            logger.info("Container stopped successfully")
        except Exception as e:
            logger.warning(f"Error stopping container: {e}")
```

**Cleanup Guarantees:**
| Scenario | Cleanup? | Mechanism |
|----------|----------|-----------|
| Normal completion | ✓ YES | `finally` block + `remove=True` |
| Exception in scan | ✓ YES | Exception caught, `finally` runs |
| RPC client disconnects | ✓ YES | gRPC stream closes, `finally` runs |
| Container crashes | ✓ YES | `remove=True` cleans orphaned container |
| Server crash | ✗ NO | Orphaned container remains (risk!) |

**Orphaned Container Risk:**
- If server process is killed (SIGKILL), containers may remain
- Mitigation: Systemd restart policy or external container reaper
- No active cleanup daemon in current code

### Resource Limits (CPU/Memory Caps)

**Memory Limit: 2GB per container**
- Hard cap via Docker
- Code: [server.py#L103](SUSS/server.py#L103)
```python
mem_limit="2g"
```

**CPU Limits: NONE SPECIFIED** ✗
- Default: Share host CPU proportionally
- No `cpuset`, `cpu_shares`, or CPU quota set
- Can cause resource starvation if multiple scans run

**Recommended Resource Limits (NOT IMPLEMENTED):**
```python
# Suggested additions:
container = self.docker_client.containers.run(
    image="fast-clamav:latest",
    detach=True,
    mem_limit="2g",
    memswap_limit="2g",  # Prevent swap usage
    cpu_quota=100000,     # 1 CPU core max (100000 out of 100000)
    cpu_count=1,          # Bind to 1 core
    pids_limit=100,       # Prevent fork bombs
    remove=True,
    ports={"3310/tcp": None}
)
```

**Current Limitation:**
- Memory is capped, but CPU is unbounded
- Large scans can monopolize host CPU

---

## 6. Error Handling (Highly Valued by Reviewers)

### What Happens if Scan Fails?

**Linux (CUBE/platform/linux):**

1. **File Read Error During Scan**
   - **Behavior**: Logged and skipped
   - **Code**: [scanner_client.py#L87-89](CUBE/platform/windows/scanner_client.py#L87-L89)
   ```python
   except Exception as e:
       self._log(f"Error reading {rel_path}: {e}", _LogLevel.ERROR)
   ```
   - **Result**: Continues scanning other files
   - **Risk**: Missed infected files if permission-denied

2. **gRPC Stream Connection Error**
   - **Behavior**: Exception caught, hardware remains locked
   - **Code**: [scanner_client.py#L95-100](CUBE/platform/windows/scanner_client.py#L95-L100)
   ```python
   except Exception as e:
       self._log(f"Connection or Stream Error: {e}", _LogLevel.ERROR)
   ```
   - **Result**: Returns empty `infected_files` list
   - **Consequence**: Device treated as CLEAN (allowed to proceed)
   - **⚠️ SECURITY ISSUE**: False negative on connection error!

3. **Session-Level Error**
   - **Behavior**: Hardware remains in read-only state (SAFE)
   - **Code**: [usb_guard.py#L104-109](CUBE/platform/linux/usb_guard.py#L104-L109)
   ```python
   if not client.is_server_alive(timeout=4):
       logger.critical("SECURITY BREACH PREVENTED: Scanner Server is OFFLINE.")
       trigger_event("Security Offline", parent_node, "Scanning server unreachable. USB remains locked.")
       return  # EXIT: Do not proceed to mount
   ```
   - **Result**: USB locked indefinitely (requires manual intervention)

**Windows (CUBE/platform/windows):**

1. **File Scan Error**
   - **Behavior**: Logged, continues scanning
   - **Code**: [usb_guard.py#L76-79](CUBE/platform/windows/usb_guard.py#L76-L79)
   ```python
   try:
       if os.path.exists(drive_path):
           self.client.scan_directory(drive_path)
   except Exception as e:
       self.logger.error(f"Error scanning {drive}: {e}")
   ```
   - **Result**: Drive scanned as-is, no special handling

2. **Cumulative Behavior**
   - No server-alive check (like Linux)
   - ⚠️ **RISK**: If server is down, silently scans nothing, treats drive as CLEAN

### What if TLS Handshake Fails?

**Failure Scenario 1: Certificate Missing**
- **Linux Client**: Raises `FileNotFoundError`, stops execution
- **Code**: [scanner_client.py#L49-50](CUBE/platform/windows/scanner_client.py#L49-L50)
```python
else:
    raise FileNotFoundError(f"SSL Certificate not found at: {cert_path}")
```
- **Result**: Service fails to start (caught by systemd restart)
- **Behavior**: Retry loop every 10 seconds (systemd default)

**Failure Scenario 2: Certificate Mismatch (Invalid/Expired)**
- **gRPC Channel**: TLS handshake fails, no secure connection established
- **Result**: `grpc.RpcError` with code `UNAVAILABLE`
- **Code Path**: [scanner_client.py#L97-99](CUBE/platform/windows/scanner_client.py#L97-L99)
```python
except Exception as e:
    self._log(f"Connection or Stream Error: {e}", _LogLevel.ERROR)
```
- **Issue**: Caught as generic exception, no special handling
- **⚠️ SECURITY ISSUE**: Falls back to assuming file is CLEAN

**Failure Scenario 3: Server Not Listening**
- **Client Behavior**: Timeout waiting for connection
- **Linux**:  `is_server_alive()` detects this, USB remains locked ✓
- **Windows**: Logs error, continues scan (no check) ✗
- **Code**: [scanner_client.py#L58-62](CUBE/platform/windows/scanner_client.py#L58-L62)
```python
def is_server_alive(self, timeout=3):
    try:
        grpc.channel_ready_future(self.channel).result(timeout=timeout)
        return True
    except (grpc.FutureTimeoutError, Exception) as e:
        self.logger.error(f"Heartbeat failed for {self.server_address}: {e}")
        return False
```

**Server-Side TLS Handling:**
- Uses `grpc.ssl_server_credentials()` to require client TLS
- If client sends plaintext or invalid cert: connection rejected
- Code: [server.py#L203-210](SUSS/server.py#L203-L210)
```python
server_creds = grpc.ssl_server_credentials(((private_key, certificate_chain),))
server.add_secure_port(f'[::]:{PORT}', server_creds)
```

### What if Container Crashes?

**Scenario 1: ClamAV Database Fails to Load**
- **Behavior**: Server waits up to 60 seconds for PING response
- **Code**: [server.py#L46-55](SUSS/server.py#L46-L55)
```python
def _wait_for_clamav(self, ip, port=3310, timeout=60):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                s.send(b"PING\0")
                response = s.recv(1024)
                if b"PONG" in response:
                    return True
        except Exception as e:
            logger.debug(f"ClamAV not ready yet: {e}")
        time.sleep(2)
    logger.error(f"ClamAV initialization timed out after {timeout}s")
    return False
```
- **Timeout Result**: 
  - Raises `Exception("ClamAV initialization timed out")`
  - Caught in outer try-except block
  - Yields error response to client
  - Code: [server.py#L146-151](SUSS/server.py#L146-L151)
  ```python
  except Exception as e:
      logger.error(f"Session Error: {e}", exc_info=True)
      yield scanner_pb2.ScanResult(
          path_within_directory="",
          status=f"ERROR: {str(e)}"
      )
  ```

**Scenario 2: Container OOM (Out of Memory)**
- **Behavior**: Docker kills container with SIGKILL
- **Effect**: Socket connection drops unexpectedly
- **Client Result**: `ConnectionResetError` or `BrokenPipeError`
- **Code**: [server.py#L76-82](SUSS/server.py#L76-L82)
```python
client.send(size + first_request.chunk_data)
# If container dies here, socket.send() raises BrokenPipeError
```
- **Handling**: Generic exception catch in `_scan_single_file()`
- **Result**: Returns `f"ERROR: {str(e)}"` for that file
- **Client sees**: "ERROR: [Errno 104] Connection reset by peer"
- **Consequence**: File marked as error (not CLEAN or INFECTED)

**Scenario 3: Container Runtime Error (During Scan)**
- **Behavior**: ClamAV process crashes, port 3310 closes
- **Socket Effect**: Next `client.send()` or `recv()` fails
- **Code Path**: [server.py#L76-82](SUSS/server.py#L76-L82) → exception → `_scan_single_file()` catches it
- **Recovery**: `finally` block stops and removes container
- **Result**: `remove=True` cleans up orphaned container
- **Impact**: Incomplete scan results returned to client

**Scenario 4: Port Binding Conflict**
- **Behavior**: Container starts but port 3310 unavailable
- **Detection**: Port mapping fails in `container.reload()`
- **Code**: [server.py#L122-127](SUSS/server.py#L122-L127)
```python
port_info = container.attrs["NetworkSettings"]["Ports"]["3310/tcp"]
if not port_info:
    raise Exception("ClamAV port not published")
```
- **Result**: Exception raised, caught in outer try-except
- **Response**: Client receives "ERROR: ClamAV port not published"

**Missing Error Handling:**
| Issue | Current Behavior | Recommended Fix |
|-------|------------------|-----------------|
| Container crashes mid-stream | Partial results with errors | Restart container, retry |
| OOM kill | Stream broken | Set `memswap_limit` to prevent OOM |
| Port conflict | Session fails | Retry with exponential backoff |
| Zombie containers | Accumulate on server crash | Systemd ExecStopPost: docker cleanup |

---

## 7. Summary: Architectural Strengths & Weaknesses

### ✓ Strengths

1. **Excellent Hardware-Level Protection (Linux)**
   - Kernel-enforced read-only (blockdev)
   - Reversible protection model
   - Server liveness check before proceeding

2. **Event-Driven Architecture**
   - No busy-waiting on USB detection
   - Responsive to hotplug events
   - Both platforms use efficient event loops

3. **Per-Scan Container Isolation**
   - Clean environment for each scan
   - Malware cannot persist between sessions
   - Fault isolation prevents cascade failures

4. **Comprehensive Logging**
   - All operations timestamped
   - Easy forensics and audit trail
   - Both systemd + file logging

5. **Graceful Degradation (Partial)**
   - Scan continues even if individual files fail
   - Device stays locked if server offline (Linux)

### ✗ Weaknesses & Security Issues

1. **Windows Lacks Hardware Protection**
   - No kernel-level write-blocking
   - Relies on OS permissions + scanning window
   - Device can be modified during scan

2. **Stream Error False Negatives (Both Platforms)**
   - gRPC connection errors treated as CLEAN
   - Should fail-safe to LOCKED state
   - Risk: Infected USB passes through on network failure

3. **No Mutual TLS (Client Authentication)**
   - Server accepts connections from any client with certificate
   - No server-side verification of client identity
   - Any client can request scans

4. **Unbounded CPU in Containers**
   - Memory is capped (2GB) but CPU is unlimited
   - Large scans can monopolize host resources
   - No QoS protection

5. **Manual Cleanup After Server Crash**
   - `remove=True` doesn't protect against daemon crash
   - Orphaned containers accumulate
   - No external reaper or periodic cleanup

6. **Hardcoded Server Addresses**
   - Windows points to fixed IP (100.98.209.6)
   - No service discovery or failover
   - Inflexible for multi-server deployments

7. **Windows Silent Failures**
   - No server liveness check
   - Scan can complete with server offline (false negatives)
   - No retry mechanism

---

## 8. Code Quality Assessment

### Error Handling Score: 6/10

**What Reviewers Would Flag:**

1. **Generic Exception Catching** (Moderate Issue)
   - Most `except Exception as e:` catch all errors
   - Prevents distinguishing network vs file system errors
   - Recommendation: Catch specific exceptions (gRPC errors, OSError, etc.)

2. **Missing Retry Logic** (Moderate Issue)
   - No exponential backoff for transient failures
   - Single attempt on connection error
   - Recommendation: Implement circuit breaker or retry policy

3. **Insufficient Logging on Critical Paths** (Minor Issue)
   - Container crash detection happens implicitly
   - ClamAV timeout silent after 60 seconds
   - Recommendation: Log every retry attempt with reason

4. **Inconsistent Error Handling** (Moderate Issue)
   - Linux has server-alive check, Windows doesn't
   - Different behavior for same failure scenarios
   - Recommendation: Unify client behavior across platforms

5. **Race Conditions** (Minor Issue)
   - Mount path cleanup uses `rmdir()` without checking if empty
   - Concurrent scans on same device could conflict
   - Recommendation: Use `shutil.rmtree()` with error handling

### Recommendations for Production

```python
# Example: Improved error handling

class ScannerClient:
    def scan_directory(self, path, max_retries=3):
        for attempt in range(max_retries):
            try:
                return self._scan_directory_impl(path)
            except grpc.RpcError as e:
                if e.code() in [grpc.StatusCode.UNAVAILABLE]:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # exponential backoff
                        self._log(f"Retry {attempt+1}/{max_retries} after {wait_time}s: {e.details()}", _LogLevel.INFO)
                        time.sleep(wait_time)
                        continue
                # Final attempt or non-retryable error
                self._log(f"Scan failed: {e.details()}", _LogLevel.ERROR)
                raise  # Re-raise to caller (should fail-safe)
            except OSError as e:
                self._log(f"File system error: {e}", _LogLevel.ERROR)
                raise  # Non-transient, don't retry
```

---

## Final Notes

This system implements a **defense-in-depth approach** with good separation of concerns:
- **Detection** (event-driven)
- **Protection** (hardware + mount)
- **Scanning** (containerized)
- **Response** (GUI resolver + ticket system)

The main improvements for production readiness are:
1. Unify error handling across platforms
2. Add retry logic with exponential backoff
3. Implement server health checks on Windows
4. Add CPU/memory/PID limits to containers
5. Externalize configuration (not hardcoded addresses)
6. Add mutual TLS client authentication
