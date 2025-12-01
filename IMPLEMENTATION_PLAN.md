# UWRX Zig Implementation Plan

## Overview

UWRX is a process supervision and tracing tool that intercepts syscalls, captures execution traces, implements network MITM proxying, and enables reproducible builds with partial rebuild support. This document provides a concrete implementation plan using the Zig programming language.

---

## Project Structure

```
uwrx/
├── build.zig                    # Zig build system
├── build.zig.zon                # Zig package manifest
├── src/
│   ├── main.zig                 # Entry point and CLI
│   ├── supervisor/
│   │   ├── mod.zig              # Supervisor module root
│   │   ├── subreaper.zig        # Subreaper registration
│   │   ├── tmpfs.zig            # tmpfs directory management
│   │   ├── lifecycle.zig        # Process lifecycle management
│   │   └── collector.zig        # Trace buffer collection
│   ├── manager/
│   │   ├── mod.zig              # Manager thread module root
│   │   ├── loader.zig           # Self-loading into upper addresses
│   │   ├── elf.zig              # ELF parsing and ld.so relocation
│   │   ├── seccomp.zig          # seccomp-bpf and unotify setup
│   │   ├── syscall_handler.zig  # Syscall interception logic
│   │   └── ipc.zig              # IPC with supervisor
│   ├── tracing/
│   │   ├── mod.zig              # Tracing module root
│   │   ├── perfetto.zig         # Perfetto trace format writer
│   │   ├── buffer.zig           # mmap trace buffer management
│   │   ├── events.zig           # Trace event definitions
│   │   ├── merger.zig           # Trace merging and compression
│   │   └── storage.zig          # Trace directory structure
│   ├── network/
│   │   ├── mod.zig              # Network module root
│   │   ├── dns.zig              # DNS server and interception
│   │   ├── proxy.zig            # HTTP/HTTPS MITM proxy
│   │   ├── tls.zig              # TLS certificate generation
│   │   ├── loopback.zig         # Loopback IP allocation per domain
│   │   └── git.zig              # Git repository mirroring
│   ├── filesystem/
│   │   ├── mod.zig              # Filesystem module root
│   │   ├── overlay.zig          # Layered filesystem view
│   │   ├── remap.zig            # Path remapping
│   │   ├── whiteout.zig         # Whiteout (deletion) handling
│   │   ├── timestamp.zig        # Timestamp/permission squashing
│   │   └── meta.zig             # File modification metadata tracking
│   ├── reproducibility/
│   │   ├── mod.zig              # Reproducibility module root
│   │   ├── prng.zig             # Hierarchical PRNG system
│   │   ├── time.zig             # Deterministic time handling
│   │   └── replay.zig           # Network/trace replay logic
│   ├── rebuild/
│   │   ├── mod.zig              # Partial rebuild module root
│   │   ├── cache.zig            # Cache hit detection
│   │   ├── whitelist.zig        # Skippable process whitelist
│   │   └── skip.zig             # Process skipping logic
│   ├── inspect/
│   │   ├── mod.zig              # Inspection module root
│   │   ├── cli.zig              # CLI inspection commands
│   │   └── tui.zig              # Interactive terminal UI
│   ├── tests/
│   │   ├── unit/                # Unit tests
│   │   └── integration/         # Integration tests
│   └── util/
│       ├── mod.zig              # Utilities module root
│       ├── linux.zig            # Linux-specific syscall wrappers
│       ├── deflate.zig          # DEFLATE compression
│       └── allocator.zig        # Custom allocators
└── docs/
    └── ...                      # Documentation
```

---

## Implementation Phases

### Phase 1: Foundation and Core Infrastructure

#### 1.1 Build System Setup
- **File**: `build.zig`, `build.zig.zon`
- **Tasks**:
  - Configure Zig build with target platforms (Linux x86_64 and aarch64 primary)
  - Set up test configuration. tests are part of main statically linked urwx executable
  - Configure release/debug modes.
  - Add dependencies (if any external Zig packages needed)

#### 1.2 Linux Syscall Interface (`src/util/linux.zig`)
- **Tasks**:
  - Wrap essential Linux syscalls not in std:
    - `prctl(PR_SET_CHILD_SUBREAPER)`
    - `seccomp(SECCOMP_SET_MODE_FILTER)` with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
    - `ioctl(SECCOMP_IOCTL_NOTIF_*)` for unotify
    - `clone3()` for process spawning with control
    - `pidfd_open()`, `pidfd_getfd()`
    - `memfd_create()` for anonymous memory
    - `fallocate()` with `FALLOC_FL_PUNCH_HOLE` and `FALLOC_FL_KEEP_SIZE`
  - Define all necessary structs: `seccomp_notif`, `seccomp_notif_resp`, etc.

#### 1.3 CLI and Entry Point (`src/main.zig`)
- **Tasks**:
  - Parse command-line arguments:
    -"uwrx run [options] -- <command> [args...]"  - Supervise a command
      - `--build <path>` - Build directory location, default is ./build
      - `--step <name>` - Step name, default is the largest step + 10, or 0 if none exist yet (cannot be specified for replay)
      - `--parent <path>` - Parent trace(s)
      - `--replay <path>` - Trace to replay
      - `--net` / `--no-net` - Network mode. For replay default is off, otherwise default is on
      - `--tmp <path>` - Location where create temporary file directory, default under /tmp
    - "test <test> [options]" - run a test case
    - "ui <path>" - examine a trace interactively
  - Initialize logging
  - Dispatch to appropriate module

---

### Phase 2: Supervisor Core

#### 2.1 Subreaper Registration (`src/supervisor/subreaper.zig`)
- **Tasks**:
  - Call `prctl(PR_SET_CHILD_SUBREAPER, 1)` to become subreaper
  - Set up `SIGCHLD` handler for child process reaping
  - Maintain process tree state
  - check if all subprocesses have ended (some might have detached by double fork) before finishing active phase

#### 2.2 tmpfs Management (`src/supervisor/tmpfs.zig`)
- **Tasks**:
  - Create unique temporary directory under /tmp or another location specified by "--tmp" option
  - Create directory structure: `<tmpdir>/traces/`
  - Implement cleanup on termination

#### 2.3 Process Lifecycle (`src/supervisor/lifecycle.zig`)
- **Tasks**:
  - Allocate deterministic pids (not OS pids):
    - Supervisor is pid 1
    - Spawned processes get 2, 3, 4, ... in spawn order
    - Maintain mapping: uwrx_pid <-> actual_os_pid
    - On replay, processes get matching pids from trace (handles racy scheduling)
  - Track all supervised processes (uwrx_pid -> process info map)
  - Handle process creation notifications from manager threads
  - Handle process termination (collect final traces, clean up)
  - Implement graceful shutdown (SIGTERM to all children)

#### 2.4 Trace Buffer Collection (`src/supervisor/collector.zig`)
- **Tasks**:
  - Periodically scan tmpfs trace directory
  - For each trace file:
    - Check if owning process still exists (`kill(pid, 0)`)
    - Read up to (file_size - 1MB) to avoid partial writes
    - Parse Perfetto events
    - Use `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` to reclaim space
  - For terminated processes: finish reading entire file, delete
  - Feed events to merger

---

### Phase 3: Manager Thread and Syscall Interception

#### 3.1 ELF Loader (`src/manager/elf.zig`)
- **Tasks**:
  - Parse ELF headers (Ehdr, Phdr)
  - Extract PT_INTERP to find dynamic linker path
  - Load ELF segments of the interpreted with correct permissions, as specified by program headers
  - Perform relocations (R_X86_64_RELATIVE, R_X86_64_GLOB_DAT, etc.)
  - Set up auxiliary vector (auxv) entries:
    - AT_PHDR, AT_PHENT, AT_PHNUM
    - AT_BASE (interpreter base)
    - AT_ENTRY
    - AT_RANDOM (point to PRNG-generated bytes)
    - AT_EXECFN

#### 3.2 Self-Loader (`src/manager/loader.zig`)
- **Tasks**:
  - On startup, mmap UWRX binary to high addresses (near top of user space)
  - Jump to high-address copy (uwrx should be statically linked and a PIC to make this easier)
  - From high-address copy:
    - Set up reduced address space for target executable
    - Load target executable's interpreter (ld.so)
    - Prepare execution environment

#### 3.3 Seccomp Setup (`src/manager/seccomp.zig`)
- **Tasks**:
  - Create BPF filter that:
    - Returns `SECCOMP_RET_USER_NOTIF` for intercepted syscalls
    - Returns `SECCOMP_RET_ALLOW` for uninteresting syscalls
  - Syscalls to intercept:
    - Process: `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `exit`, `exit_group`
    - File: `open`, `openat`, `openat2`, `creat`, `unlink`, `unlinkat`, `rename`, `renameat`, `renameat2`, `mkdir`, `mkdirat`, `rmdir`, `stat`, `fstat`, `lstat`, `fstatat`, `access`, `faccessat`, `readlink`, `readlinkat`, `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`, `lchown`, `fchownat`, `utimensat`, `futimesat`
    - Network: `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `getsockopt`, `setsockopt`, `getpeername`, `getsockname`
    - Random: `getrandom`
    - Time: `clock_gettime`, `gettimeofday`, `time`
  - Install filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
  - Return listener fd for manager thread

#### 3.4 Syscall Handler (`src/manager/syscall_handler.zig`)
- **Tasks**:
  - Event loop on seccomp notify fd using `ioctl(SECCOMP_IOCTL_NOTIF_RECV)`
  - For each notification:
    - Read syscall number and arguments
    - Dispatch to appropriate handler
    - Respond with `ioctl(SECCOMP_IOCTL_NOTIF_SEND)`:
      - `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for pass-through
      - Custom return value / errno for modified syscalls
  - Handlers for each syscall category:
    - **Process spawning**: Intercept clone/fork/execve to set up manager thread in child
    - **File operations**: Redirect through uwrx overlay filesystem, as implemented by uwrx (this is in-process)
    - **Network**: Redirect through supervisor's sockets
    - **Random**: Return PRNG-generated values
    - **Time**: Return deterministic time values

#### 3.5 Manager-Supervisor IPC (`src/manager/ipc.zig`)
- **Tasks**:
  - Create Unix domain socket pair for low-latency IPC
  - Protocol messages:
    - `PROCESS_START` - Notify process start
    - `OPEN_SOCKET` - Request supervisor to open network socket
    - `PROCESS_EXIT` - Notify process termination
  - Use eventfd for synchronization where needed

---

### Phase 4: Tracing System

#### 4.1 Perfetto Format Writer (`src/tracing/perfetto.zig`)
- **Tasks**:
  - Implement Perfetto trace packet format (protobuf-based)
  - Define packet types:
    - `TrackDescriptor` - Define tracks for processes/threads
    - `TrackEvent` - Events with timestamps
    - `ProcessDescriptor`, `ThreadDescriptor`
    - `ClockSnapshot` for custom timestamp clock
  - Use incremental encoding with `TrackEventDefaults`
  - Implement DEFLATE compression wrapper (only for final, merged trace)

#### 4.2 Trace Buffer (`src/tracing/buffer.zig`)
- **Tasks**:
  - Open trace file in "traces/" using process pid as filename
  - mmap 1MB window with `MAP_SHARED | MAP_POPULATE`
  - Track write offset within window
  - When write_offset > (1MB - MAX_EVENT_SIZE):
    - Advance mmap window by (1MB - MAX_EVENT_SIZE) rounded to page
    - Update file mappings
  - Provide `writeEvent(bytes)` interface

#### 4.3 Trace Events (`src/tracing/events.zig`)
- **Tasks**:
  - Define event types:
    - Process events: spawn, exec, exit
    - File events: open, read, write, close, stat, unlink, rename
    - Network events: connect, send, recv, dns_lookup
    - Output events: stdout_write, stderr_write
  - Each event includes:
    - Timestamp (incremental)
    - Process/thread IDs
    - Event-specific data
  - Serialize to Perfetto format

#### 4.4 Trace Merger (`src/tracing/merger.zig`)
- **Tasks**:
  - Collect events from multiple trace buffers
  - Sort by timestamp
  - Deduplicate if needed
  - Compress with DEFLATE
  - Write to final trace file

#### 4.5 Trace Storage (`src/tracing/storage.zig`)
- **Tasks**:
  - Implement directory structure: `build/<step>/<attempt>/`
  - Write/read step files:
    - `cmd` - Command line
    - `options` - UWRX options
  - Write/read attempt files:
    - `perfetto` - Compressed trace
    - `ca.pem` - CA certificate
    - `seed.txt` - PRNG seed (hex)
    - `files.meta` - File modification metadata (process tracking)
  - Manage `files/` directory with whiteouts
  - Manage `net/` directory structure
  - Handle `parent/` symlinks
  - Handle `replay` symlink

---

### Phase 5: Network Isolation and MITM

#### 5.1 Loopback IP Allocation (`src/network/loopback.zig`)
- **Tasks**:
  - Maintain domain -> loopback IP mapping
  - Allocate random IPs from 127.0.0.0/8 for IPv4 (avoid 127.0.0.0/24 and 127.255.255.0/24)
  - Allocate from ::1/128 range for IPv6 (similarly, avoid addresses with existing meaning)
  - Persist mappings in trace: `net/<domain>/ip4.txt`, `ip6.txt`
  - Reverse lookup: loopback IP -> domain

#### 5.2 DNS Server (`src/network/dns.zig`)
- **Tasks**:
  - Bind UDP socket on 127.0.0.1:53 (also use DNS interception)
  - expose fake /etc/resolv.conf with this address
  - Parse DNS queries (A, AAAA records)
  - For each domain lookup:
    - In capture mode: Perform real DNS lookup, record result
    - In replay mode: Do nothing
  - Return allocated loopback IP instead of real IP
  - Record DNS events in trace

#### 5.3 TLS Certificate Generation (`src/network/tls.zig`)
- **Tasks**:
  - Generate CA certificate and private key on startup
  - Store in trace as `ca.pem`
  - On TLS connection:
    - Extract domain from loopback IP mapping
    - Generate domain certificate signed by CA
    - Store per-domain cert: `net/<domain>/cert.pem`
  - Use Zig's std.crypto or link to a TLS library (e.g., BearSSL bindings)

#### 5.4 MITM Proxy (`src/network/proxy.zig`)
- **Tasks**:
  - Listen on allocated loopback IPs
  - For TCP connections:
    - Determine if TLS (by attempting TLS handshake detection)
    - For TLS: Present generated certificate, decrypt traffic
    - Forward to real destination (capture) or replay from cache
  - Record all request/response data in plaintext
  - Special handling:
    - HTTP file downloads: Save body as file under `net/<domain>/<path>`
    - Git protocol: Mirror repository (see 5.5)

#### 5.5 Git Repository Mirroring (`src/network/git.zig`)
- **Tasks**:
  - Detect git protocol (git://, http(s) git requests)
  - For git operations:
    - Clone/fetch from upstream into bare repository
    - Store under `net/<domain>/<path>/<repo>.git/`
    - Serve subsequent requests from local mirror
  - Handle git-upload-pack, git-receive-pack protocols

---

### Phase 6: Filesystem Overlay

#### 6.1 Overlay Filesystem (`src/filesystem/overlay.zig`)
- **Tasks**:
  - Build layered view from parent traces and per-process versions
  - For process P reading file X, resolution order:
    1. Find all `files-<pid>/X` where `pid < P` (versions written before P ran)
    2. Use the one with largest such pid
    3. If none exist, use `files/X` (the original first version)
    4. If not in `files/` at all, check parent traces' `files/` directories
    5. Finally, real filesystem (read-only base)
  - Note: `files-<pid>/` not `files/<pid>/` to distinguish from normal paths like `/123/foo`
  - Pids are deterministic (allocated by uwrx), not actual OS pids
  - Handle whiteouts (deleted files) - same resolution logic applies

#### 6.2 Path Remapping (`src/filesystem/remap.zig`)
- **Tasks**:
  - Intercept file paths in syscalls
  - Check overlay for file existence
  - Remap to appropriate layer path
  - Special paths:
    - CA certificate locations (inject CA cert)
    - /dev/urandom, /dev/random (redirect to PRNG)
    - /etc/resolv.conf

#### 6.3 Whiteout Handling (`src/filesystem/whiteout.zig`)
- **Tasks**:
  - On file deletion: Create character device 0/0 (overlayfs whiteout)
  - On file lookup: Check for whiteout, return ENOENT
  - On directory listing: Filter out whiteout entries

#### 6.4 Timestamp Squashing (`src/filesystem/timestamp.zig`)
- **Tasks**:
  - Assign deterministic timestamps per layer:
    - Base layer: T0
    - Parent layers: T0 + layer_index * interval
    - Current layer: T0 + (num_parents + 1) * interval
  - Intercept stat() family syscalls
  - Replace actual timestamps with layer timestamps
  - Normalize permissions as needed

#### 6.5 File Modification Metadata (`src/filesystem/meta.zig`)
- **Tasks**:
  - Track per-process file versions for correct partial rebuild
  - Problem: if A writes foo, B reads foo, C overwrites foo - need B's input version to determine if B can be skipped
  - Directory structure:
    - `files/<path>` - first written version (original)
    - `files-<pid>/<path>` - overwrites by process pid (only when file already existed)
  - Note: `files-<pid>/` not `files/<pid>/` to distinguish from normal paths
  - On file write:
    - If file doesn't exist in `files/`: write to `files/<path>`
    - If file already exists in `files/`: write to `files-<pid>/<path>`
  - Deduplication: use hardlinks or reflinks when file content is identical
  - Pids are deterministic (allocated by uwrx: 1=supervisor, 2, 3, 4... for spawned processes)
  - No need to track pid for base `files/` - pid ordering determines visibility
  - Maintain `files.meta` for inspection (not for resolution):
    - `<relative_path>\t<pid>\t<operation>\t<exec_path>`
  - Operations tracked: `create`, `write`, `delete`, `rename_to`, `rename_from`, `mkdir`, `rmdir`, `chmod`, `chown`
  - Provide query interface:
    - `resolveFile(path, as_of_pid) -> ?FilePath` - which actual file would this pid see?
  - Essential for partial rebuild cache hit detection

---

### Phase 7: Reproducibility

#### 7.1 Hierarchical PRNG (`src/reproducibility/prng.zig`)
- **Tasks**:
  - Generate root seed on fresh run, store in `seed.txt`
  - Load seed on replay
  - Implement hierarchical derivation:
    - Each process gets derived seed from parent's seed + pid of a matching process from replay trace
    - Thread-local PRNG state
  - Service getrandom() syscalls
  - Provide AT_RANDOM bytes
  - Implement /dev/urandom emulation

#### 7.2 Deterministic Time (`src/reproducibility/time.zig`)
- **Tasks**:
  - Record start time on fresh run
  - Intercept time syscalls:
    - `clock_gettime()` - Return deterministic time
    - `gettimeofday()` - Return deterministic time
    - `time()` - Return deterministic time
  - Options:
    - Frozen time (always same value)
    - Advancing time (controlled increment)

#### 7.3 Parent Logic (`src/reproducibility/parent.zig`)
- **Tasks**:
  - For network: Return recorded responses
  - For file operations: Use "files" in the overlay
  
---

### Phase 8: Partial Rebuild

#### 8.1 Process Whitelist (`src/rebuild/whitelist.zig`)
- **Tasks**:
  - Default whitelist: `cc`, `gcc`, `g++`, `clang`, `clang++`, `ld`, `ar`, `as`, etc.
  - Configuration to add/remove from whitelist
  - Match executable name against whitelist

#### 8.2 Cache Hit Detection (`src/rebuild/cache.zig`)
- **Tasks**:
  - For each process in replay trace:
    - Collect all read file paths
    - Collect all written file paths
  - On current run, before executing whitelisted process P:
    - For each file X that P read in replay trace:
      - Resolve which version P would see now using pid ordering:
        - Find `files-<pid>/X` with largest `pid < P`, or `files/X` if none
      - Compare content with what P saw in replay trace
    - If all input versions match: cache hit, can skip
    - If any input differs: must re-execute
  - Per-process versioning via `files-<pid>/` directories is essential:
    - Example: A writes foo, B reads foo, C overwrites foo
    - B sees `files/foo` (original), C's version goes to `files-<C_pid>/foo`
    - On replay, can verify B's input by checking `files/foo`
  - Deterministic pids ensure same logical process gets same pid on replay

#### 8.3 Process Skipping (`src/rebuild/skip.zig`)
- **Tasks**:
  - If cache hit detected for whitelisted process:
    - Don't actually execute the process
    - Replay stdout/stderr from parent trace
    - Replay exit status
  - Record skip event in trace

---

### Phase 9: Inspection Tools

#### 9.1 CLI Inspector (`src/inspect/cli.zig`)
- **Tasks**:
  - Commands:
    - `uwrx inspect files <trace>` - List read/modified files
    - `uwrx inspect files <trace> --who` - Show which process modified each file (uses files.meta)
    - `uwrx inspect files <trace> --by-pid <pid>` - List files modified by specific process
    - `uwrx inspect procs <trace>` - List/tree processes
    - `uwrx inspect output <trace> [pid]` - Show stdout/stderr
    - `uwrx inspect events <trace>` - Raw event listing
    - `uwrx check <trace>` - Validate trace consistency
  - Format options: text, json

#### 9.2 Terminal UI (`src/inspect/tui.zig`)
- **Tasks**:
  - Process hierarchy tree view
  - Navigate with arrow keys
  - Show process details on selection:
    - Command line
    - Environment
    - File operations
    - Network operations
    - stdout/stderr
  - Search functionality
  - Use Zig terminal library or raw escape sequences

---

## Implementation Order

### Milestone 1: Basic Supervision (MVP)
1. Build system setup
2. Linux syscall wrappers
3. CLI parsing
4. Subreaper registration
5. Basic process spawning (without interception)
6. tmpfs setup
7. Basic trace writing (file-based events)

### Milestone 2: Syscall Interception
1. ELF parsing
2. Self-loader (high-address relocation)
3. ld.so loading
4. Seccomp filter setup
5. Basic syscall handler (pass-through with logging)
6. Manager-supervisor IPC

### Milestone 3: File Interception
1. File syscall interception
2. Overlay filesystem (single layer)
3. Path remapping
4. Timestamp squashing
5. Multi-layer overlay (parent traces)
6. Whiteout handling

### Milestone 4: Tracing
1. Perfetto format writer
2. mmap trace buffers
3. Trace event definitions
4. Trace collection from tmpfs
5. Trace merging and compression
6. Trace storage structure

### Milestone 5: Network Isolation
1. Loopback IP allocation
2. DNS interception
3. TCP proxy (no TLS)
4. TLS certificate generation
5. HTTPS MITM proxy
6. Network recording in trace

### Milestone 6: Reproducibility
1. Hierarchical PRNG
2. getrandom/AT_RANDOM interception
3. Time interception
4. Network replay from trace

### Milestone 7: Advanced Features
1. Git repository mirroring
2. File download caching
3. Partial rebuild detection
4. Process skipping

### Milestone 8: Polish
1. CLI inspection commands
2. Terminal UI
3. Perfetto UI compatibility
4. Documentation
5. Comprehensive testing

---

## Key Technical Challenges

### 1. Self-Loading and Address Space Management
- UWRX must load itself into high addresses while leaving space for target
- Requires careful virtual memory management
- Must handle ASLR

### 2. seccomp with USER_NOTIF
- Linux 5.0+ required for `SECCOMP_USER_NOTIF`
- Race conditions between checking and acting (TOCTOU)
- Use `SECCOMP_IOCTL_NOTIF_ID_VALID` to verify notification still valid

### 3. Manager Thread Without seccomp
- Manager thread must be created before seccomp filter
- Use `clone()` with `CLONE_VM` but separate seccomp context
- Careful synchronization needed

### 4. TLS Certificate Generation
- Need crypto library (Zig std.crypto or external)
- X.509 certificate generation
- Proper certificate chain

### 5. Trace Buffer Race Conditions
- Multiple processes writing to tmpfs simultaneously
- Supervisor reading while processes write
- Use atomic operations and careful offset management

---

## Dependencies

### Required
- Zig 0.13+ (or latest stable)
- Linux 5.0+ (for seccomp USER_NOTIF)
- x86_64 architecture (initial target)

### Optional/Recommended
- BearSSL or similar (for TLS, if std.crypto insufficient)
- zlib or Zig's std.compress.deflate (for trace compression)

---

## Testing Strategy

### Unit Tests
- Each module has corresponding test file
- Test syscall wrappers with mock kernel interfaces
- Test ELF parsing with sample binaries
- Test Perfetto format with known-good traces

### Integration Tests
- Simple process supervision (hello world)
- Multi-process supervision (fork/exec)
- File operation tracing
- Network interception
- Full capture/replay cycle
- Partial rebuild scenarios

### Stress Tests
- Many concurrent processes
- Large file operations
- Heavy network traffic
- Long-running processes

---

## Notes

- Start with x86_64 Linux only; other architectures can be added later
- Consider using Zig's async for I/O-heavy supervisor operations
- Profile memory usage - trace buffers can grow large
- Consider memory-mapped trace files for large traces
- Implement proper signal handling throughout
