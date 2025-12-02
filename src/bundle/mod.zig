//! Bundle module
//!
//! Implements bundled executables support, similar to busybox.
//! Allows uwrx to be distributed as a single binary containing a complete toolchain.

const std = @import("std");

pub const format = @import("format.zig");
pub const lookup = @import("lookup.zig");
pub const execute = @import("execute.zig");
pub const data = @import("data.zig");
pub const create = @import("create.zig");

/// Bundle state
pub const BundleState = struct {
    allocator: std.mem.Allocator,
    /// Bundled executables index
    executables: std.StringHashMap(BundledExec),
    /// Bundled data overlays
    data_overlays: std.StringHashMap(DataOverlay),

    pub fn init(allocator: std.mem.Allocator) BundleState {
        return .{
            .allocator = allocator,
            .executables = std.StringHashMap(BundledExec).init(allocator),
            .data_overlays = std.StringHashMap(DataOverlay).init(allocator),
        };
    }

    pub fn deinit(self: *BundleState) void {
        self.executables.deinit();
        self.data_overlays.deinit();
    }

    /// Load bundled content from own executable
    pub fn loadFromSelf(self: *BundleState) !void {
        try format.loadBundledSections(self);
    }

    /// Check if an executable is bundled
    pub fn hasBundled(self: *BundleState, name: []const u8) bool {
        return self.executables.contains(name);
    }

    /// Get bundled executable info
    pub fn getBundled(self: *BundleState, name: []const u8) ?BundledExec {
        return self.executables.get(name);
    }
};

/// Bundled executable info
pub const BundledExec = struct {
    /// Name of the executable
    name: []const u8,
    /// Offset within uwrx binary
    offset: usize,
    /// Size of executable
    size: usize,
    /// Entry point offset within executable
    entry_offset: usize,
};

/// Data overlay info
pub const DataOverlay = struct {
    /// Name (matches executable name)
    name: []const u8,
    /// Offset within uwrx binary
    offset: usize,
    /// Size of data section
    size: usize,
    /// Compression type
    compression: CompressionType,
};

pub const CompressionType = enum {
    none,
    deflate,
    zstd,
    squashfs,
};

test {
    _ = format;
    _ = lookup;
    _ = execute;
    _ = data;
    _ = create;
}
