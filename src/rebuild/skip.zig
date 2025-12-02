//! Process skipping logic
//!
//! Handles skipping processes during partial rebuild by replaying
//! their output and exit status.

const std = @import("std");
const replay = @import("../reproducibility/replay.zig");

/// Skip result
pub const SkipResult = struct {
    /// Exit status to return
    exit_status: u32,
    /// stdout data to replay
    stdout: ?[]const u8,
    /// stderr data to replay
    stderr: ?[]const u8,
};

/// Process skipping handler
pub const SkipHandler = struct {
    allocator: std.mem.Allocator,
    replay_state: ?*replay.ReplayState,

    pub fn init(allocator: std.mem.Allocator, replay_state: ?*replay.ReplayState) SkipHandler {
        return .{
            .allocator = allocator,
            .replay_state = replay_state,
        };
    }

    /// Get skip result for a process
    pub fn getSkipResult(self: *SkipHandler, pid: u32) ?SkipResult {
        const rs = self.replay_state orelse return null;

        const exit_status = rs.getExitStatus(pid) orelse return null;

        return .{
            .exit_status = exit_status,
            .stdout = rs.getStdout(pid),
            .stderr = rs.getStderr(pid),
        };
    }

    /// Execute skip (replay output)
    pub fn executeSkip(self: *SkipHandler, result: SkipResult) !void {
        _ = self;

        // Write stdout
        if (result.stdout) |data| {
            const stdout = std.io.getStdOut();
            try stdout.writeAll(data);
        }

        // Write stderr
        if (result.stderr) |data| {
            const stderr = std.io.getStdErr();
            try stderr.writeAll(data);
        }
    }
};

/// Record for trace that process was skipped
pub const SkipRecord = struct {
    pid: u32,
    original_pid: u32, // PID from replay trace
    reason: []const u8,
};

test "SkipHandler without replay" {
    const allocator = std.testing.allocator;

    var handler = SkipHandler.init(allocator, null);

    // Without replay state, should return null
    const result = handler.getSkipResult(2);
    try std.testing.expect(result == null);
}
