//! Process lifecycle management
//!
//! Tracks all supervised processes, their deterministic PIDs,
//! and their lifecycle state.

const std = @import("std");

/// Process information
pub const ProcessInfo = struct {
    /// Host OS PID
    host_pid: std.os.linux.pid_t,
    /// Deterministic uwrx PID (2, 3, 4, ... in spawn order)
    uwrx_pid: u32,
    /// Versioned string PID for unmatched processes during replay
    versioned_pid: ?[]const u8 = null,
    /// Parent uwrx PID (null for root process)
    parent_uwrx_pid: ?u32,
    /// Command line (if known)
    command: ?[]const []const u8 = null,
    /// Exit status (set when process exits)
    exit_status: ?u32 = null,
    /// Whether process has exited
    exited: bool = false,
};

/// Process state manager
pub const ProcessState = struct {
    allocator: std.mem.Allocator,
    /// Map from host PID to process info
    by_host_pid: std.AutoHashMap(std.os.linux.pid_t, *ProcessInfo),
    /// Map from uwrx PID to process info
    by_uwrx_pid: std.AutoHashMap(u32, *ProcessInfo),
    /// Next uwrx PID to assign
    next_uwrx_pid: u32 = 2, // 1 is supervisor
    /// For unmatched processes during replay
    unmatched_counters: std.AutoHashMap(u32, u32),

    pub fn init(allocator: std.mem.Allocator) ProcessState {
        return .{
            .allocator = allocator,
            .by_host_pid = std.AutoHashMap(std.os.linux.pid_t, *ProcessInfo).init(allocator),
            .by_uwrx_pid = std.AutoHashMap(u32, *ProcessInfo).init(allocator),
            .unmatched_counters = std.AutoHashMap(u32, u32).init(allocator),
        };
    }

    pub fn deinit(self: *ProcessState) void {
        var it = self.by_host_pid.valueIterator();
        while (it.next()) |info_ptr| {
            if (info_ptr.*.versioned_pid) |v| {
                self.allocator.free(v);
            }
            self.allocator.destroy(info_ptr.*);
        }
        self.by_host_pid.deinit();
        self.by_uwrx_pid.deinit();
        self.unmatched_counters.deinit();
    }

    /// Register a new process
    pub fn registerProcess(
        self: *ProcessState,
        host_pid: std.os.linux.pid_t,
        uwrx_pid: u32,
        parent_uwrx_pid: ?u32,
    ) !void {
        const info = try self.allocator.create(ProcessInfo);
        info.* = .{
            .host_pid = host_pid,
            .uwrx_pid = uwrx_pid,
            .parent_uwrx_pid = parent_uwrx_pid,
        };

        try self.by_host_pid.put(host_pid, info);
        try self.by_uwrx_pid.put(uwrx_pid, info);

        if (uwrx_pid >= self.next_uwrx_pid) {
            self.next_uwrx_pid = uwrx_pid + 1;
        }
    }

    /// Allocate the next uwrx PID
    pub fn allocateUwrxPid(self: *ProcessState) u32 {
        const pid = self.next_uwrx_pid;
        self.next_uwrx_pid += 1;
        return pid;
    }

    /// Get process info by host PID
    pub fn getByHostPid(self: *ProcessState, host_pid: std.os.linux.pid_t) ?*ProcessInfo {
        return self.by_host_pid.get(host_pid);
    }

    /// Get process info by uwrx PID
    pub fn getByUwrxPid(self: *ProcessState, uwrx_pid: u32) ?*ProcessInfo {
        return self.by_uwrx_pid.get(uwrx_pid);
    }

    /// Mark process as exited
    pub fn markExited(self: *ProcessState, host_pid: std.os.linux.pid_t, status: u32) !void {
        if (self.by_host_pid.get(host_pid)) |info| {
            info.exited = true;
            info.exit_status = status;
        }
    }

    /// Get exit status for an uwrx PID
    pub fn getExitStatus(self: *ProcessState, uwrx_pid: u32) ?u8 {
        if (self.by_uwrx_pid.get(uwrx_pid)) |info| {
            if (info.exit_status) |status| {
                // Extract exit code from wait status
                if (std.os.linux.W.IFEXITED(status)) {
                    return std.os.linux.W.EXITSTATUS(status);
                }
                return 128 + @as(u8, @truncate(std.os.linux.W.TERMSIG(status)));
            }
        }
        return null;
    }

    /// Check if all processes have exited
    pub fn allExited(self: *ProcessState) bool {
        var it = self.by_host_pid.valueIterator();
        while (it.next()) |info_ptr| {
            if (!info_ptr.*.exited) {
                return false;
            }
        }
        return true;
    }

    /// Get count of active (non-exited) processes
    pub fn activeCount(self: *ProcessState) usize {
        var count: usize = 0;
        var it = self.by_host_pid.valueIterator();
        while (it.next()) |info_ptr| {
            if (!info_ptr.*.exited) {
                count += 1;
            }
        }
        return count;
    }

    /// Generate versioned PID string for unmatched process during replay
    pub fn generateVersionedPid(self: *ProcessState, before_uwrx_pid: u32) ![]u8 {
        const counter = self.unmatched_counters.get(before_uwrx_pid) orelse 0;
        try self.unmatched_counters.put(before_uwrx_pid, counter + 1);

        if (counter == 0) {
            return std.fmt.allocPrint(self.allocator, "{d}.1", .{before_uwrx_pid});
        } else {
            return std.fmt.allocPrint(self.allocator, "{d}.1.{d}", .{ before_uwrx_pid, counter + 1 });
        }
    }
};

test "ProcessState lifecycle" {
    const allocator = std.testing.allocator;

    var state = ProcessState.init(allocator);
    defer state.deinit();

    // Register processes
    try state.registerProcess(1000, 2, null);
    try state.registerProcess(1001, 3, 2);

    try std.testing.expectEqual(@as(usize, 2), state.by_host_pid.count());
    try std.testing.expect(!state.allExited());

    // Mark one as exited
    try state.markExited(1000, 0);
    try std.testing.expect(!state.allExited());

    // Mark both as exited
    try state.markExited(1001, 0);
    try std.testing.expect(state.allExited());
}

test "versioned PID generation" {
    const allocator = std.testing.allocator;

    var state = ProcessState.init(allocator);
    defer state.deinit();

    const v1 = try state.generateVersionedPid(3);
    defer allocator.free(v1);
    try std.testing.expectEqualStrings("3.1", v1);

    const v2 = try state.generateVersionedPid(3);
    defer allocator.free(v2);
    try std.testing.expectEqualStrings("3.1.2", v2);
}
