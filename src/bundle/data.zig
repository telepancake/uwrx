//! Bundled data overlay access
//!
//! Provides file lookup interface for bundled data overlays.

const std = @import("std");
const mod = @import("mod.zig");

/// Data overlay reader
pub const DataOverlayReader = struct {
    allocator: std.mem.Allocator,
    overlay: mod.DataOverlay,
    /// Decompressed index (for squashfs)
    index: ?*anyopaque,

    pub fn init(allocator: std.mem.Allocator, overlay: mod.DataOverlay) DataOverlayReader {
        return .{
            .allocator = allocator,
            .overlay = overlay,
            .index = null,
        };
    }

    pub fn deinit(self: *DataOverlayReader) void {
        _ = self;
        // Clean up index if allocated
    }

    /// Check if file exists in overlay
    pub fn exists(self: *DataOverlayReader, path: []const u8) bool {
        _ = self;
        _ = path;
        // Would check squashfs index
        return false;
    }

    /// Read file from overlay
    pub fn read(self: *DataOverlayReader, path: []const u8) ?[]const u8 {
        _ = self;
        _ = path;
        // Would decompress and return file contents
        return null;
    }

    /// List directory in overlay
    pub fn list(self: *DataOverlayReader, path: []const u8) ?[]const []const u8 {
        _ = self;
        _ = path;
        // Would return directory listing
        return null;
    }

    /// Get file stat info
    pub fn stat(self: *DataOverlayReader, path: []const u8) ?StatInfo {
        _ = self;
        _ = path;
        return null;
    }
};

/// File stat info
pub const StatInfo = struct {
    mode: u32,
    size: u64,
    uid: u32,
    gid: u32,
};

/// Common bundled data paths
pub const CommonPaths = struct {
    /// Headers
    pub const include = "/usr/include";
    /// Libraries
    pub const lib = "/usr/lib";
    /// GCC specifics
    pub const gcc = "/usr/lib/gcc";
    /// Binutils
    pub const binutils = "/usr/bin";
};

/// Create data overlay for bundled executable
pub fn createOverlay(allocator: std.mem.Allocator, exe_name: []const u8) !?DataOverlayReader {
    // Check if this executable has bundled data
    const state = @import("lookup.zig").global_state orelse return null;

    const overlay = state.data_overlays.get(exe_name) orelse return null;

    return DataOverlayReader.init(allocator, overlay);
}

test "DataOverlayReader" {
    const allocator = std.testing.allocator;

    var reader = DataOverlayReader.init(allocator, .{
        .name = "test",
        .offset = 0,
        .size = 0,
        .compression = .none,
    });
    defer reader.deinit();

    try std.testing.expect(!reader.exists("/test"));
}
