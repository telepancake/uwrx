//! Subreaper registration and child process reaping
//!
//! Makes uwrx the subreaper so all orphaned processes in the subtree
//! become children of uwrx rather than init.

const std = @import("std");
const linux = @import("../util/linux.zig");

/// Signal handler state
var sigchld_received: bool = false;

/// Become a subreaper process
pub fn becomeSubreaper() !void {
    try linux.setChildSubreaper(true);
    try setupSigchldHandler();
}

/// Set up SIGCHLD handler
fn setupSigchldHandler() !void {
    const handler = std.os.linux.Sigaction{
        .handler = .{ .handler = sigchldHandler },
        .mask = std.os.linux.empty_sigset,
        .flags = linux.SA_RESTART | linux.SA_NOCLDSTOP,
    };

    const result = std.os.linux.sigaction(linux.SIG.CHLD, &handler, null);
    if (result != 0) {
        return error.SigactionFailed;
    }
}

fn sigchldHandler(_: c_int) callconv(.C) void {
    sigchld_received = true;
}

/// Result of waiting for children
pub const WaitResult = struct {
    has_terminated: bool = false,
    terminated_pids: std.BoundedArray(std.os.linux.pid_t, 64) = .{},
    exit_status: u32 = 0,
};

/// Wait for and reap terminated children
pub fn waitForChildren() WaitResult {
    var result = WaitResult{};

    if (!sigchld_received) {
        return result;
    }
    sigchld_received = false;

    // Reap all terminated children
    while (true) {
        var status: u32 = 0;
        const pid = std.os.linux.waitpid(-1, &status, std.os.linux.W.NOHANG);

        if (pid > 0) {
            result.has_terminated = true;
            result.exit_status = status;
            result.terminated_pids.append(@intCast(pid)) catch {
                // Too many terminated processes at once, will catch rest next time
                break;
            };
        } else {
            break;
        }
    }

    return result;
}

/// Send SIGTERM to all processes in process group
pub fn terminateAll() void {
    // Send SIGTERM to process group
    _ = std.os.linux.kill(0, linux.SIG.TERM);
}

/// Check if a process is still alive
pub fn isAlive(pid: std.os.linux.pid_t) bool {
    const result = std.os.linux.kill(pid, 0);
    return result == 0;
}

test "subreaper setup" {
    // This test requires root or CAP_SYS_ADMIN in a real environment
    // Just verify the function exists
    _ = becomeSubreaper;
}
