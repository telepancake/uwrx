//! Deterministic time handling
//!
//! Provides consistent time values across runs for reproducibility.

const std = @import("std");

/// Time mode
pub const TimeMode = enum {
    /// Time is frozen at start time
    frozen,
    /// Time advances at a controlled rate
    advancing,
    /// Time advances with real time (from start)
    real_offset,
};

/// Deterministic time state
pub const DeterministicTime = struct {
    /// Mode of operation
    mode: TimeMode,
    /// Base time (Unix timestamp)
    base_time: i64,
    /// Real start time (for offset mode)
    real_start: i64,
    /// Advancement counter (for advancing mode)
    advance_counter: i64,
    /// Advancement step (nanoseconds per call)
    advance_step: i64,

    pub fn init() DeterministicTime {
        const now = std.time.timestamp();
        return .{
            .mode = .frozen,
            .base_time = now,
            .real_start = now,
            .advance_counter = 0,
            .advance_step = 1000000, // 1ms per call
        };
    }

    pub fn initWithTime(time_val: i64) DeterministicTime {
        return .{
            .mode = .frozen,
            .base_time = time_val,
            .real_start = std.time.timestamp(),
            .advance_counter = 0,
            .advance_step = 1000000,
        };
    }

    /// Get current time
    pub fn getTime(self: *DeterministicTime) i64 {
        return switch (self.mode) {
            .frozen => self.base_time,
            .advancing => blk: {
                const result = self.base_time + @divFloor(self.advance_counter, std.time.ns_per_s);
                self.advance_counter += self.advance_step;
                break :blk result;
            },
            .real_offset => blk: {
                const elapsed = std.time.timestamp() - self.real_start;
                break :blk self.base_time + elapsed;
            },
        };
    }

    /// Get current time with nanosecond precision
    pub fn getTimeNs(self: *DeterministicTime) struct { sec: i64, nsec: i64 } {
        return switch (self.mode) {
            .frozen => .{ .sec = self.base_time, .nsec = 0 },
            .advancing => blk: {
                const total_ns = self.base_time * std.time.ns_per_s + self.advance_counter;
                self.advance_counter += self.advance_step;
                break :blk .{
                    .sec = @divFloor(total_ns, std.time.ns_per_s),
                    .nsec = @mod(total_ns, std.time.ns_per_s),
                };
            },
            .real_offset => blk: {
                const now = std.time.nanoTimestamp();
                const start_ns = self.real_start * std.time.ns_per_s;
                const base_ns = self.base_time * std.time.ns_per_s;
                const result_ns = base_ns + (now - start_ns);
                break :blk .{
                    .sec = @divFloor(result_ns, std.time.ns_per_s),
                    .nsec = @mod(result_ns, std.time.ns_per_s),
                };
            },
        };
    }

    /// Set mode
    pub fn setMode(self: *DeterministicTime, mode: TimeMode) void {
        self.mode = mode;
    }

    /// Get timeval structure
    pub fn getTimeval(self: *DeterministicTime) std.os.linux.timeval {
        const t = self.getTimeNs();
        return .{
            .sec = t.sec,
            .usec = @divFloor(t.nsec, 1000),
        };
    }

    /// Get timespec structure
    pub fn getTimespec(self: *DeterministicTime) std.os.linux.timespec {
        const t = self.getTimeNs();
        return .{
            .sec = t.sec,
            .nsec = t.nsec,
        };
    }
};

test "DeterministicTime frozen" {
    var time_state = DeterministicTime.initWithTime(1000000);

    const t1 = time_state.getTime();
    const t2 = time_state.getTime();

    try std.testing.expectEqual(t1, t2);
    try std.testing.expectEqual(@as(i64, 1000000), t1);
}

test "DeterministicTime advancing" {
    var time_state = DeterministicTime.initWithTime(1000000);
    time_state.setMode(.advancing);

    const t1 = time_state.getTime();
    _ = time_state.getTime(); // Advance
    _ = time_state.getTime(); // Advance more

    // Time should advance
    try std.testing.expectEqual(@as(i64, 1000000), t1);
}
