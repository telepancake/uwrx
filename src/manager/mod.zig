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
        };
    }

    pub fn deinit(self: *ManagerState) void {
        if (self.seccomp_fd >= 0) {
            std.os.linux.close(self.seccomp_fd);
        }
        self.supervisor_conn.deinit();
    }
};

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

    // Fork the process
    const pid = std.os.linux.fork();

    if (pid == 0) {
        // Child process
        sup_conn.closeParentEnd();

        // Initialize manager state
        var state = ManagerState.init(allocator, sup_conn, uwrx_pid);
        defer state.deinit();

        // Run the managed process setup and execution
        runManaged(&state, command) catch |err| {
            std.debug.print("Manager error: {}\n", .{err});
            std.process.exit(127);
        };
        std.process.exit(0);
    } else if (pid > 0) {
        // Parent process (supervisor)
        sup_conn.closeChildEnd();

        // Notify supervisor of new process
        try sup_conn.sendMessage(.{ .process_start = .{ .host_pid = pid, .uwrx_pid = uwrx_pid } });

        return pid;
    } else {
        return error.ForkFailed;
    }
}

/// Run in the managed process context
fn runManaged(state: *ManagerState, command: []const []const u8) !void {
    // Load target executable
    const exe_path = command[0];
    var exe_info = try elf.loadExecutable(state.allocator, exe_path);
    defer exe_info.deinit();

    // Set up seccomp filter with USER_NOTIF
    state.seccomp_fd = try seccomp.setupFilter();

    // Create thread for the actual program execution
    // The manager thread will handle syscall notifications

    // For now, use a simple exec approach
    // In full implementation, this would:
    // 1. Load uwrx to high addresses
    // 2. Set up ld.so from PT_INTERP
    // 3. Start target thread with seccomp
    // 4. Handle notifications in manager thread

    // Execute the command
    const argv = try toCStringArray(state.allocator, command);
    defer {
        for (argv) |arg| {
            if (arg) |a| state.allocator.free(std.mem.span(a));
        }
        state.allocator.free(argv);
    }

    // Get environment
    const envp = std.c.environ;

    // Execute (this replaces the current process image)
    const result = std.os.linux.execve(argv[0].?, argv.ptr, @ptrCast(envp));
    if (result != 0) {
        return error.ExecFailed;
    }
}

fn toCStringArray(allocator: std.mem.Allocator, args: []const []const u8) ![:null]?[*:0]const u8 {
    var result = try allocator.alloc(?[*:0]const u8, args.len + 1);
    errdefer allocator.free(result);

    for (args, 0..) |arg, i| {
        const cstr = try allocator.allocSentinel(u8, arg.len, 0);
        @memcpy(cstr, arg);
        result[i] = cstr.ptr;
    }
    result[args.len] = null;

    return result[0..args.len :null];
}

test {
    _ = loader;
    _ = elf;
    _ = seccomp;
    _ = syscall_handler;
    _ = ipc;
}
