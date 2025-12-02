//! Reproducibility module
//!
//! Provides deterministic PRNG, time, and replay support for reproducible builds.

const std = @import("std");

pub const prng = @import("prng.zig");
pub const time = @import("time.zig");
pub const replay = @import("replay.zig");

/// Reproducibility state for a run
pub const ReproducibilityState = struct {
    allocator: std.mem.Allocator,
    prng_state: prng.HierarchicalPrng,
    time_state: time.DeterministicTime,

    pub fn init(allocator: std.mem.Allocator, seed: ?u64) ReproducibilityState {
        const actual_seed = seed orelse @as(u64, @intCast(std.time.timestamp()));

        return .{
            .allocator = allocator,
            .prng_state = prng.HierarchicalPrng.init(actual_seed),
            .time_state = time.DeterministicTime.init(),
        };
    }

    /// Get the root seed
    pub fn getSeed(self: *const ReproducibilityState) u64 {
        return self.prng_state.root_seed;
    }

    /// Get random bytes for a process
    pub fn getRandomBytes(self: *ReproducibilityState, pid: u32, buf: []u8) void {
        self.prng_state.fillBytes(pid, buf);
    }

    /// Get current time
    pub fn getTime(self: *ReproducibilityState) i64 {
        return self.time_state.getTime();
    }

    /// Get AT_RANDOM bytes for a process
    pub fn getAtRandom(self: *ReproducibilityState, pid: u32) [16]u8 {
        return self.prng_state.getAtRandom(pid);
    }
};

test {
    _ = prng;
    _ = time;
    _ = replay;
}
