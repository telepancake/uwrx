//! Partial rebuild module
//!
//! Implements cache hit detection and process skipping for faster rebuilds.

const std = @import("std");

pub const cache = @import("cache.zig");
pub const whitelist = @import("whitelist.zig");
pub const skip = @import("skip.zig");

/// Rebuild state
pub const RebuildState = struct {
    allocator: std.mem.Allocator,
    whitelist_state: whitelist.Whitelist,
    cache_state: cache.CacheState,

    pub fn init(allocator: std.mem.Allocator) RebuildState {
        return .{
            .allocator = allocator,
            .whitelist_state = whitelist.Whitelist.init(allocator),
            .cache_state = cache.CacheState.init(allocator),
        };
    }

    pub fn deinit(self: *RebuildState) void {
        self.whitelist_state.deinit();
        self.cache_state.deinit();
    }

    /// Check if a process can be skipped
    pub fn canSkip(self: *RebuildState, exe_name: []const u8, pid: u32) bool {
        // Must be on whitelist
        if (!self.whitelist_state.isWhitelisted(exe_name)) {
            return false;
        }

        // Check cache hit
        return self.cache_state.checkHit(pid);
    }
};

test {
    _ = cache;
    _ = whitelist;
    _ = skip;
}
