//! Timestamp squashing for reproducibility
//!
//! Assigns deterministic timestamps to files based on their layer,
//! regardless of actual modification times.

const std = @import("std");

/// Base timestamp for all files (Unix epoch + 1 year)
pub const BASE_TIMESTAMP: i64 = 365 * 24 * 60 * 60; // 1971-01-01

/// Interval between layer timestamps (1 day)
pub const LAYER_INTERVAL: i64 = 24 * 60 * 60;

/// Timestamp state for a run
pub const TimestampState = struct {
    /// Number of parent layers
    num_parents: u32,
    /// Current layer index (num_parents + 1)
    current_layer: u32,

    pub fn init(num_parents: u32) TimestampState {
        return .{
            .num_parents = num_parents,
            .current_layer = num_parents + 1,
        };
    }

    /// Get timestamp for a given layer
    pub fn getLayerTimestamp(self: *const TimestampState, layer_index: u32) i64 {
        return BASE_TIMESTAMP + @as(i64, layer_index) * LAYER_INTERVAL;
    }

    /// Get timestamp for parent layer
    pub fn getParentTimestamp(self: *const TimestampState, parent_index: u32) i64 {
        return self.getLayerTimestamp(parent_index);
    }

    /// Get timestamp for current layer
    pub fn getCurrentTimestamp(self: *const TimestampState) i64 {
        return self.getLayerTimestamp(self.current_layer);
    }

    /// Get timestamp for base sources (layer 0)
    pub fn getBaseTimestamp(_: *const TimestampState) i64 {
        return BASE_TIMESTAMP;
    }
};

/// Modified stat structure with squashed timestamps
pub const SquashedStat = struct {
    mode: u32,
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    uid: u32,
    gid: u32,
    nlink: u64,
    ino: u64,
    dev: u64,
};

/// Squash timestamps in a stat result
pub fn squashStat(stat: std.os.linux.Stat, timestamp: i64) SquashedStat {
    return .{
        .mode = stat.mode,
        .size = @intCast(stat.size),
        .atime = timestamp,
        .mtime = timestamp,
        .ctime = timestamp,
        .uid = normalizeUid(stat.uid),
        .gid = normalizeGid(stat.gid),
        .nlink = @intCast(stat.nlink),
        .ino = @intCast(stat.ino),
        .dev = @intCast(stat.dev),
    };
}

/// Normalize UID for reproducibility
pub fn normalizeUid(uid: u32) u32 {
    // Map all UIDs to 1000 (typical first user)
    _ = uid;
    return 1000;
}

/// Normalize GID for reproducibility
pub fn normalizeGid(gid: u32) u32 {
    // Map all GIDs to 1000 (typical first user group)
    _ = gid;
    return 1000;
}

/// Normalize file mode for reproducibility
pub fn normalizeMode(mode: u32) u32 {
    // Keep type bits, normalize permission bits
    const type_bits = mode & std.os.linux.S.IFMT;

    // Directories: 755, files: 644 (or 755 if executable)
    if (type_bits == std.os.linux.S.IFDIR) {
        return type_bits | 0o755;
    } else if (mode & 0o111 != 0) {
        // Executable
        return type_bits | 0o755;
    } else {
        return type_bits | 0o644;
    }
}

/// Fill a timespec with deterministic values
pub fn fillTimespec(ts: *std.os.linux.timespec, timestamp: i64) void {
    ts.sec = timestamp;
    ts.nsec = 0;
}

test "TimestampState" {
    const state = TimestampState.init(2);

    try std.testing.expectEqual(BASE_TIMESTAMP, state.getBaseTimestamp());
    try std.testing.expectEqual(BASE_TIMESTAMP, state.getParentTimestamp(0));
    try std.testing.expectEqual(BASE_TIMESTAMP + LAYER_INTERVAL, state.getParentTimestamp(1));
    try std.testing.expectEqual(BASE_TIMESTAMP + 3 * LAYER_INTERVAL, state.getCurrentTimestamp());
}

test "normalizeMode" {
    // Directory
    try std.testing.expectEqual(@as(u32, std.os.linux.S.IFDIR | 0o755), normalizeMode(std.os.linux.S.IFDIR | 0o777));

    // Non-executable file
    try std.testing.expectEqual(@as(u32, std.os.linux.S.IFREG | 0o644), normalizeMode(std.os.linux.S.IFREG | 0o600));

    // Executable file
    try std.testing.expectEqual(@as(u32, std.os.linux.S.IFREG | 0o755), normalizeMode(std.os.linux.S.IFREG | 0o700));
}
