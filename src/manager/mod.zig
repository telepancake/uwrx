//! Manager thread module
//!
//! The manager thread runs in the same address space as the target process
//! but is not subject to seccomp filtering. It handles syscall notifications
//! and coordinates with the supervisor.

const std = @import("std");
const linux = @import("../util/linux.zig");
const supervisor = @import("../supervisor/mod.zig");

pub const loader = @import("loader.zig");
pub const elf = @import("elf.zig");
pub const seccomp = @import("seccomp.zig");
pub const syscall_handler = @import("syscall_handler.zig");
pub const ipc = @import("ipc.zig");

/// Manager thread state
pub const ManagerState = struct {
    allocator: std.mem.Allocator,
    supervisor_conn: ipc.SupervisorConnection,
    seccomp_fd: linux.fd_t,
    uwrx_pid: u32,
    host_pid: std.os.linux.pid_t,
    /// TID of the target thread (to be traced by manager)
    target_tid: std.os.linux.pid_t,
    /// Whether manager thread is ready
    manager_ready: std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        sup_conn: ipc.SupervisorConnection,
        uwrx_pid: u32,
    ) ManagerState {
        return .{
            .allocator = allocator,
            .supervisor_conn = sup_conn,
            .seccomp_fd = -1,
            .uwrx_pid = uwrx_pid,
            .host_pid = std.os.linux.getpid(),
            .target_tid = 0,
            .manager_ready = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *ManagerState) void {
        if (self.seccomp_fd >= 0) {
            std.os.linux.close(self.seccomp_fd);
        }
        self.supervisor_conn.deinit();
    }
};

// mmap failure value (equivalent to (void*)-1)
const MAP_FAILED: usize = ~@as(usize, 0);

// PTRACE options flags
const PTRACE_O_TRACESYSGOOD: usize = 0x00000001;
const PTRACE_O_TRACEFORK: usize = 0x00000002;
const PTRACE_O_TRACEVFORK: usize = 0x00000004;
const PTRACE_O_TRACECLONE: usize = 0x00000008;
const PTRACE_O_TRACEEXEC: usize = 0x00000010;
const PTRACE_O_TRACEEXIT: usize = 0x00000040;

// PTRACE commands not in std
const PTRACE_SEIZE: usize = 0x4206;
const PTRACE_INTERRUPT: usize = 0x4207;
const PTRACE_LISTEN: usize = 0x4208;

/// Spawn a managed process with syscall interception
pub fn spawnManaged(
    allocator: std.mem.Allocator,
    sup: *supervisor.Supervisor,
    command: []const []const u8,
    parent_uwrx_pid: ?u32,
) !std.os.linux.pid_t {
    _ = parent_uwrx_pid;

    // Create IPC channels
    var sup_conn = try ipc.SupervisorConnection.create();
    errdefer sup_conn.deinit();

    // Allocate uwrx PID
    const uwrx_pid = sup.process_state.allocateUwrxPid();

    // Fork the process - supervisor does NOT trace the child
    const fork_result = std.os.linux.fork();
    const pid: std.os.linux.pid_t = @bitCast(@as(u32, @truncate(fork_result)));

    if (pid == 0) {
        // Child process - the managed process
        sup_conn.closeParentEnd();

        // Initialize manager state
        var state = ManagerState.init(allocator, sup_conn, uwrx_pid);

        // Run the managed process with internal manager thread
        const exit_code = runManagedProcess(&state, command);
        std.process.exit(exit_code);
    } else if (pid > 0) {
        // Parent process (supervisor) - just track the child, don't trace it
        sup_conn.closeChildEnd();

        // Try to notify supervisor of new process (may fail if child already exec'd)
        sup_conn.sendMessage(.{ .process_start = .{ .host_pid = pid, .uwrx_pid = uwrx_pid } }) catch {
            // Child already exec'd, IPC is broken - that's OK
        };

        return pid;
    } else {
        return error.ForkFailed;
    }
}

/// Thread context passed to manager thread
const ManagerThreadContext = struct {
    state: *ManagerState,
    command: []const []const u8,
};

/// Stack size for manager thread
const MANAGER_STACK_SIZE: usize = 64 * 1024; // 64KB

/// Run the managed process with proper manager thread architecture
///
/// Architecture:
/// 1. Create manager thread with clone(CLONE_VM | CLONE_THREAD)
/// 2. Manager thread installs seccomp filter (ioctl NOT intercepted, so it can handle notifications)
/// 3. Manager thread enters notification loop
/// 4. Original thread waits for manager, then loads target via ELF loader (NO EXECVE)
/// 5. Original thread jumps to loaded code - syscalls are now intercepted by manager
fn runManagedProcess(state: *ManagerState, command: []const []const u8) u8 {
    // Allocate stack for manager thread
    const stack_result = std.os.linux.mmap(
        null,
        MANAGER_STACK_SIZE,
        std.os.linux.PROT.READ | std.os.linux.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .STACK = true },
        -1,
        0,
    );

    if (stack_result == MAP_FAILED) {
        std.debug.print("Failed to allocate manager thread stack\n", .{});
        return 127;
    }

    // Stack grows down, so start at the top
    const stack_top = stack_result + MANAGER_STACK_SIZE;

    // Prepare context for manager thread
    var ctx = ManagerThreadContext{
        .state = state,
        .command = command,
    };

    // Store target TID for manager to track
    state.target_tid = std.os.linux.gettid();

    // Create manager thread with CLONE_VM | CLONE_THREAD
    // CLONE_VM: share address space (so manager can write directly to target's memory)
    // CLONE_THREAD: same thread group
    // CLONE_SIGHAND: share signal handlers
    // CLONE_FS: share filesystem info
    // CLONE_FILES: share file descriptors
    const clone_flags = linux.CLONE_VM | linux.CLONE_THREAD | linux.CLONE_SIGHAND |
        linux.CLONE_FS | linux.CLONE_FILES;

    const clone_result = std.os.linux.clone(
        managerThreadEntry,
        stack_top,
        @intCast(clone_flags),
        @intFromPtr(&ctx),
        null,
        0,
        null,
    );

    if (clone_result == 0 or clone_result > 0x8000_0000_0000_0000) {
        std.debug.print("Failed to create manager thread\n", .{});
        return 127;
    }

    // Wait for manager thread to be ready
    while (!state.manager_ready.load(.acquire)) {
        // Spin wait - manager thread will set this after installing seccomp
        std.atomic.spinLoopHint();
    }

    // Manager is ready - now load and run target (NO EXECVE!)
    return loadAndRunTarget(state, command);
}

/// Entry point for manager thread
fn managerThreadEntry(arg: usize) callconv(.C) u8 {
    const ctx: *ManagerThreadContext = @ptrFromInt(arg);
    managerThreadMain(ctx.state);
    return 0;
}

/// Manager thread main function - sets up syscall interception and handles events
fn managerThreadMain(state: *ManagerState) void {
    const target_tid = state.target_tid;

    // Try seccomp USER_NOTIF first (more efficient)
    if (trySeccompInterception(state)) {
        return;
    }

    // Fall back to ptrace if seccomp is not available
    std.debug.print("Seccomp not available, falling back to ptrace\n", .{});
    tryPtraceInterception(state, target_tid);
}

/// Try to set up seccomp-based syscall interception
fn trySeccompInterception(state: *ManagerState) bool {
    // Set up seccomp filter - this applies to ALL threads in the process
    const seccomp_fd = seccomp.setupFilter() catch |err| {
        std.debug.print("Seccomp setup failed: {}\n", .{err});
        return false;
    };

    state.seccomp_fd = seccomp_fd;

    // Signal that we're ready - target can now proceed
    state.manager_ready.store(true, .release);

    // Run the seccomp notification event loop
    runSeccompLoop(state, seccomp_fd);
    return true;
}

/// Run the seccomp notification event loop
fn runSeccompLoop(state: *ManagerState, seccomp_fd: linux.fd_t) void {
    _ = state;

    while (true) {
        // Receive notification
        const notif = seccomp.recvNotification(seccomp_fd) catch |err| {
            if (err == error.RecvFailed) {
                // Probably no more processes to trace
                break;
            }
            continue;
        };

        // For now, just continue all syscalls (allow them to proceed)
        // Full implementation would handle each syscall type appropriately
        const resp = seccomp.continueResponse(notif.id);
        seccomp.sendResponse(seccomp_fd, &resp) catch {
            // Process may have exited
            continue;
        };
    }
}

/// Try to set up ptrace-based syscall interception (fallback)
fn tryPtraceInterception(state: *ManagerState, target_tid: std.os.linux.pid_t) void {
    // Attach to the target thread using PTRACE_SEIZE
    // PTRACE_SEIZE is better than ATTACH for thread tracing
    const seize_result = std.os.linux.syscall4(
        .ptrace,
        PTRACE_SEIZE,
        @as(usize, @intCast(target_tid)),
        0,
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
            PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT,
    );

    if (seize_result != 0) {
        std.debug.print("PTRACE_SEIZE failed: {}\n", .{seize_result});
        // Signal ready anyway so target can proceed (without tracing)
        state.manager_ready.store(true, .release);
        return;
    }

    // Signal that we're ready - target can now proceed
    state.manager_ready.store(true, .release);

    // Run ptrace event loop
    runPtraceLoop(target_tid);
}

/// Run the ptrace event loop
fn runPtraceLoop(target_tid: std.os.linux.pid_t) void {
    var status: u32 = 0;
    while (true) {
        const wait_result = std.os.linux.waitpid(target_tid, &status, 0);

        if (wait_result > 0x7fff_ffff) {
            // waitpid error - target probably exited
            break;
        }

        if (std.posix.W.IFEXITED(status)) {
            // Target exited normally
            break;
        } else if (std.posix.W.IFSIGNALED(status)) {
            // Target killed by signal
            break;
        } else if (std.posix.W.IFSTOPPED(status)) {
            // Target stopped - continue it
            _ = std.os.linux.syscall4(
                .ptrace,
                std.os.linux.PTRACE.CONT,
                @as(usize, @intCast(target_tid)),
                0,
                0,
            );
        }
    }
}

/// Load target executable and jump to it
fn loadAndRunTarget(state: *ManagerState, command: []const []const u8) u8 {
    const exe_path = command[0];
    std.debug.print("loadAndRunTarget: loading {s}\n", .{exe_path});

    // Try to load as ELF
    var exe_info = elf.loadExecutable(state.allocator, exe_path) catch |err| {
        if (err == error.IsScript) {
            // Already handled script case in runManagedProcess
            std.debug.print("Script not properly resolved\n", .{});
            return 127;
        }
        std.debug.print("Failed to load executable: {}\n", .{err});
        return 127;
    };
    defer exe_info.deinit();

    // Open file for loading segments
    const file = std.fs.openFileAbsolute(exe_path, .{}) catch {
        std.debug.print("Failed to open executable: {s}\n", .{exe_path});
        return 127;
    };
    defer file.close();

    // Calculate base address for PIE or use fixed address for non-PIE
    const base_addr: u64 = if (exe_info.is_pie) 0x10000 else 0;

    // Load ELF segments into memory
    elf.loadSegments(state.allocator, file, exe_info.phdrs, base_addr) catch |err| {
        std.debug.print("Failed to load segments: {}\n", .{err});
        return 127;
    };

    // If the executable needs a dynamic linker, we need to load it too
    var interp_entry: u64 = 0;
    if (exe_info.interp) |interp_path| {
        // Load the interpreter (ld.so)
        var interp_info = elf.loadExecutable(state.allocator, interp_path) catch {
            std.debug.print("Failed to load interpreter: {s}\n", .{interp_path});
            return 127;
        };
        defer interp_info.deinit();

        const interp_file = std.fs.openFileAbsolute(interp_path, .{}) catch {
            std.debug.print("Failed to open interpreter\n", .{});
            return 127;
        };
        defer interp_file.close();

        // Load interpreter at a high address to avoid conflicts
        const interp_base: u64 = 0x7f00_0000_0000;
        elf.loadSegments(state.allocator, interp_file, interp_info.phdrs, interp_base) catch {
            std.debug.print("Failed to load interpreter segments\n", .{});
            return 127;
        };

        interp_entry = interp_base + interp_info.entry;
    }

    // Set up the stack with arguments, environment, and auxiliary vector
    const stack_result = setupStack(state.allocator, command, exe_info, base_addr, interp_entry);
    if (stack_result == null) {
        std.debug.print("Failed to set up stack\n", .{});
        return 127;
    }

    const stack_ptr = stack_result.?;
    const entry_point = if (interp_entry != 0) interp_entry else base_addr + exe_info.entry;

    // Jump to the entry point
    // This requires inline assembly to set up registers and jump
    jumpToEntry(entry_point, stack_ptr);
}

/// Set up the initial stack for the target
fn setupStack(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    exe_info: elf.ExecutableInfo,
    base_addr: u64,
    interp_base: u64,
) ?u64 {
    _ = exe_info;
    _ = interp_base;

    // Allocate a new stack
    const stack_size: usize = 8 * 1024 * 1024; // 8MB
    const stack = std.os.linux.mmap(
        null,
        stack_size,
        std.os.linux.PROT.READ | std.os.linux.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .STACK = true, .GROWSDOWN = true },
        -1,
        0,
    );

    if (stack == MAP_FAILED) {
        return null;
    }

    var sp = stack + stack_size;

    // Build argv pointers
    var argv_ptrs = allocator.alloc(u64, args.len + 1) catch return null;
    defer allocator.free(argv_ptrs);

    // Copy argument strings to stack
    for (args, 0..) |arg, i| {
        sp -= arg.len + 1;
        const dest: [*]u8 = @ptrFromInt(sp);
        @memcpy(dest[0..arg.len], arg);
        dest[arg.len] = 0;
        argv_ptrs[i] = sp;
    }
    argv_ptrs[args.len] = 0;

    // Get environment
    const environ = std.c.environ;
    var envp_count: usize = 0;
    while (environ[envp_count] != null) : (envp_count += 1) {}

    var envp_ptrs = allocator.alloc(u64, envp_count + 1) catch return null;
    defer allocator.free(envp_ptrs);

    // Copy environment strings
    for (0..envp_count) |i| {
        const env = std.mem.span(environ[i].?);
        sp -= env.len + 1;
        const dest: [*]u8 = @ptrFromInt(sp);
        @memcpy(dest[0..env.len], env);
        dest[env.len] = 0;
        envp_ptrs[i] = sp;
    }
    envp_ptrs[envp_count] = 0;

    // Align stack to 16 bytes
    sp = sp & ~@as(u64, 0xF);

    // Build auxiliary vector
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_ENTRY: u64 = 9;
    const AT_UID: u64 = 11;
    const AT_EUID: u64 = 12;
    const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14;
    const AT_RANDOM: u64 = 25;

    // Auxv entries (type, value pairs)
    const auxv = [_]u64{
        AT_PAGESZ, 4096,
        AT_PHDR,   base_addr + 64, // Approximate - should be actual phdr location
        AT_PHENT,  56,
        AT_PHNUM,  2, // Approximate
        AT_ENTRY,  base_addr,
        AT_UID,    std.os.linux.getuid(),
        AT_EUID,   std.os.linux.geteuid(),
        AT_GID,    std.os.linux.getgid(),
        AT_EGID,   std.os.linux.getegid(),
        AT_RANDOM, sp - 16, // Point to some "random" bytes
        AT_NULL,   0,
    };

    // Push auxv
    sp -= auxv.len * 8;
    const auxv_dest: [*]u64 = @ptrFromInt(sp);
    @memcpy(auxv_dest[0..auxv.len], &auxv);

    // Push envp
    sp -= (envp_count + 1) * 8;
    const envp_dest: [*]u64 = @ptrFromInt(sp);
    @memcpy(envp_dest[0 .. envp_count + 1], envp_ptrs);

    // Push argv
    sp -= (args.len + 1) * 8;
    const argv_dest: [*]u64 = @ptrFromInt(sp);
    @memcpy(argv_dest[0 .. args.len + 1], argv_ptrs);

    // Push argc
    sp -= 8;
    const argc_dest: *u64 = @ptrFromInt(sp);
    argc_dest.* = args.len;

    return sp;
}

/// Jump to the entry point with the given stack pointer
fn jumpToEntry(entry: u64, stack_ptr: u64) noreturn {
    // Use inline assembly to set up registers and jump
    // Clear registers and jump to entry with stack_ptr as RSP
    asm volatile (
        \\mov %[sp], %%rsp
        \\xor %%rax, %%rax
        \\xor %%rbx, %%rbx
        \\xor %%rcx, %%rcx
        \\xor %%rdx, %%rdx
        \\xor %%rsi, %%rsi
        \\xor %%rdi, %%rdi
        \\xor %%rbp, %%rbp
        \\xor %%r8, %%r8
        \\xor %%r9, %%r9
        \\xor %%r10, %%r10
        \\xor %%r11, %%r11
        \\xor %%r12, %%r12
        \\xor %%r13, %%r13
        \\xor %%r14, %%r14
        \\xor %%r15, %%r15
        \\jmp *%[entry]
        :
        : [sp] "r" (stack_ptr),
          [entry] "r" (entry),
    );
    unreachable;
}

test {
    _ = loader;
    _ = elf;
    _ = seccomp;
    _ = syscall_handler;
    _ = ipc;
}
