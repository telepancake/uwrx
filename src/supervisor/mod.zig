//! Supervisor module - main process supervision and coordination
//!
//! The supervisor is responsible for:
//! - Becoming a subreaper to collect all orphaned processes
//! - Managing temporary directories for trace buffers
//! - Coordinating process lifecycle events
//! - Collecting and merging trace data

const std = @import("std");
const main = @import("../main.zig");
const Options = main.Options;

pub const subreaper = @import("subreaper.zig");
pub const tempdir = @import("tempdir.zig");
pub const lifecycle = @import("lifecycle.zig");
pub const collector = @import("collector.zig");

/// Supervisor state
pub const Supervisor = struct {
    allocator: std.mem.Allocator,
    options: *const Options,
    temp_state: tempdir.TempDir,
    process_state: lifecycle.ProcessState,
    collector_state: collector.Collector,
    running: bool = true,

    pub fn init(allocator: std.mem.Allocator, options: *const Options) !Supervisor {
        // Set up subreaper
        try subreaper.becomeSubreaper();

        // Create temp directory
        var temp_state = try tempdir.TempDir.init(allocator, options.tmp_dir);
        errdefer temp_state.deinit();

        // Initialize process state
        var process_state = lifecycle.ProcessState.init(allocator);

        // Initialize collector
        var collector_state = try collector.Collector.init(allocator, temp_state.traces_dir);

        return .{
            .allocator = allocator,
            .options = options,
            .temp_state = temp_state,
            .process_state = process_state,
            .collector_state = collector_state,
        };
    }

    pub fn deinit(self: *Supervisor) void {
        self.collector_state.deinit();
        self.process_state.deinit();
        self.temp_state.deinit();
    }

    /// Main supervision loop
    pub fn supervise(self: *Supervisor, command: []const []const u8) !u8 {
        const manager_mod = @import("../manager/mod.zig");

        // Start the main process
        const root_pid = try manager_mod.spawnManaged(
            self.allocator,
            self,
            command,
            null, // No parent process
        );

        // Register root process
        try self.process_state.registerProcess(root_pid, 2, null);

        // Main supervision loop
        while (self.running) {
            // Handle SIGCHLD and reap children
            const wait_result = subreaper.waitForChildren();

            if (wait_result.has_terminated) {
                for (wait_result.terminated_pids.slice()) |pid| {
                    try self.handleProcessExit(pid, wait_result.exit_status);
                }
            }

            // Collect traces
            try self.collector_state.collect();

            // Check if all processes have exited
            if (self.process_state.allExited()) {
                self.running = false;
            }

            // Small sleep to avoid busy-waiting
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        // Final trace collection
        try self.collector_state.collectFinal();

        // Get exit status of root process
        return self.process_state.getExitStatus(2) orelse 1;
    }

    fn handleProcessExit(self: *Supervisor, host_pid: std.os.linux.pid_t, status: u32) !void {
        // Mark process as exited
        try self.process_state.markExited(host_pid, status);

        // Collect final trace data for this process
        try self.collector_state.finalizeProcess(host_pid);
    }
};

/// Main entry point for running a supervised command
pub fn run(allocator: std.mem.Allocator, options: *Options) !void {
    var sup = try Supervisor.init(allocator, options);
    defer sup.deinit();

    const exit_code = try sup.supervise(options.command);
    std.process.exit(exit_code);
}

test {
    _ = subreaper;
    _ = tempdir;
    _ = lifecycle;
    _ = collector;
}
