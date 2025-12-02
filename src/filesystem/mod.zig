//! Filesystem module
//!
//! Implements the layered filesystem view that isolates processes
//! from the real filesystem while providing controlled access.

const std = @import("std");

pub const overlay = @import("overlay.zig");
pub const remap = @import("remap.zig");
pub const whiteout = @import("whiteout.zig");
pub const timestamp = @import("timestamp.zig");
pub const meta = @import("meta.zig");

/// Filesystem state for a supervised run
pub const FilesystemState = struct {
    allocator: std.mem.Allocator,
    overlay_state: overlay.OverlayState,
    meta_tracker: meta.MetaTracker,

    pub fn init(allocator: std.mem.Allocator, config: Config) !FilesystemState {
        var overlay_state = try overlay.OverlayState.init(allocator, config.sources, config.parents);
        errdefer overlay_state.deinit();

        var meta_tracker = meta.MetaTracker.init(allocator, config.files_dir);

        return .{
            .allocator = allocator,
            .overlay_state = overlay_state,
            .meta_tracker = meta_tracker,
        };
    }

    pub fn deinit(self: *FilesystemState) void {
        self.meta_tracker.deinit();
        self.overlay_state.deinit();
    }

    /// Resolve a path for reading
    pub fn resolvePath(self: *FilesystemState, path: []const u8, as_of_pid: u32) !?[]const u8 {
        return self.overlay_state.resolve(path, as_of_pid);
    }

    /// Get file for writing (handles copy-on-write)
    pub fn openForWrite(self: *FilesystemState, path: []const u8, pid: u32) ![]const u8 {
        return self.meta_tracker.getWritePath(path, pid);
    }

    /// Record a file modification
    pub fn recordWrite(self: *FilesystemState, path: []const u8, pid: u32) !void {
        try self.meta_tracker.recordModification(path, pid);
    }

    /// Check if file exists in overlay
    pub fn exists(self: *FilesystemState, path: []const u8, as_of_pid: u32) bool {
        return self.overlay_state.exists(path, as_of_pid);
    }

    /// List directory contents
    pub fn listDir(self: *FilesystemState, path: []const u8, as_of_pid: u32) ![]const []const u8 {
        return self.overlay_state.listDir(path, as_of_pid);
    }
};

/// Configuration for filesystem initialization
pub const Config = struct {
    /// Source mappings
    sources: []const SourceMapping,
    /// Parent trace directories
    parents: []const []const u8,
    /// Output files directory
    files_dir: []const u8,
    /// Bundled data overlay (if running bundled executable)
    bundle_data: ?[]const u8 = null,
};

/// Source mapping from command line
pub const SourceMapping = struct {
    dst: []const u8,
    priority: i32,
    source: []const u8,
};

test {
    _ = overlay;
    _ = remap;
    _ = whiteout;
    _ = timestamp;
    _ = meta;
}
