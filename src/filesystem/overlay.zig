//! Overlay filesystem implementation
//!
//! Provides a layered view of files from multiple sources:
//! 1. Bundled data (highest priority)
//! 2. files-<pid>/ directories (current run modifications)
//! 3. files/ directory (current run first writes)
//! 4. Sources (in priority order)
//! 5. Parent traces

const std = @import("std");
const whiteout = @import("whiteout.zig");

/// Layer type
pub const LayerType = enum {
    bundle_data,
    process_files,
    base_files,
    source,
    parent,
};

/// A single layer in the overlay
pub const Layer = struct {
    layer_type: LayerType,
    /// Base path for this layer
    path: []const u8,
    /// Priority (for sources)
    priority: i32,
    /// Process ID (for process_files layers)
    pid: ?u32,
};

/// Overlay filesystem state
pub const OverlayState = struct {
    allocator: std.mem.Allocator,
    layers: std.ArrayList(Layer),

    pub fn init(
        allocator: std.mem.Allocator,
        sources: []const struct { dst: []const u8, priority: i32, source: []const u8 },
        parents: []const []const u8,
    ) !OverlayState {
        var layers = std.ArrayList(Layer).init(allocator);
        errdefer layers.deinit();

        // Add source layers (sorted by priority)
        for (sources) |source| {
            try layers.append(.{
                .layer_type = .source,
                .path = source.source,
                .priority = source.priority,
                .pid = null,
            });
        }

        // Add parent layers
        for (parents) |parent| {
            try layers.append(.{
                .layer_type = .parent,
                .path = parent,
                .priority = 0,
                .pid = null,
            });
        }

        // Sort layers by priority (higher first)
        std.mem.sort(Layer, layers.items, {}, struct {
            fn lessThan(_: void, a: Layer, b: Layer) bool {
                return a.priority > b.priority;
            }
        }.lessThan);

        return .{
            .allocator = allocator,
            .layers = layers,
        };
    }

    pub fn deinit(self: *OverlayState) void {
        self.layers.deinit();
    }

    /// Add a process-specific files layer
    pub fn addProcessLayer(self: *OverlayState, path: []const u8, pid: u32) !void {
        try self.layers.append(.{
            .layer_type = .process_files,
            .path = path,
            .priority = @intCast(pid), // Higher PIDs have higher priority
            .pid = pid,
        });
    }

    /// Add base files layer
    pub fn addBaseLayer(self: *OverlayState, path: []const u8) !void {
        try self.layers.insert(0, .{
            .layer_type = .base_files,
            .path = path,
            .priority = 0,
            .pid = null,
        });
    }

    /// Add bundled data layer (highest priority)
    pub fn addBundleLayer(self: *OverlayState, path: []const u8) !void {
        try self.layers.append(.{
            .layer_type = .bundle_data,
            .path = path,
            .priority = std.math.maxInt(i32),
            .pid = null,
        });
    }

    /// Resolve a path to its actual location
    /// Returns null if file doesn't exist in any layer
    pub fn resolve(self: *OverlayState, path: []const u8, as_of_pid: u32) ?[]const u8 {
        // Check process-specific layers first (highest pid <= as_of_pid wins)
        var best_pid_layer: ?*const Layer = null;
        var best_pid: u32 = 0;

        for (self.layers.items) |*layer| {
            if (layer.layer_type == .process_files) {
                if (layer.pid) |layer_pid| {
                    if (layer_pid <= as_of_pid and layer_pid > best_pid) {
                        if (self.existsInLayer(layer, path)) {
                            // Check for whiteout
                            if (whiteout.isWhiteout(layer.path, path)) {
                                return null; // File was deleted
                            }
                            best_pid_layer = layer;
                            best_pid = layer_pid;
                        }
                    }
                }
            }
        }

        if (best_pid_layer) |layer| {
            return layer.path;
        }

        // Check other layers in order
        for (self.layers.items) |*layer| {
            switch (layer.layer_type) {
                .process_files => continue, // Already checked
                .bundle_data, .base_files, .source, .parent => {
                    if (self.existsInLayer(layer, path)) {
                        if (!whiteout.isWhiteout(layer.path, path)) {
                            return layer.path;
                        }
                    }
                },
            }
        }

        return null;
    }

    /// Check if file exists in any layer
    pub fn exists(self: *OverlayState, path: []const u8, as_of_pid: u32) bool {
        return self.resolve(path, as_of_pid) != null;
    }

    /// Check if file exists in a specific layer
    fn existsInLayer(_: *OverlayState, layer: *const Layer, path: []const u8) bool {
        var full_path_buf: [4096]u8 = undefined;
        const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ layer.path, path }) catch return false;

        const stat_result = std.fs.cwd().statFile(full_path);
        return if (stat_result) |_| true else |_| false;
    }

    /// List directory contents from all visible layers
    pub fn listDir(self: *OverlayState, path: []const u8, as_of_pid: u32) ![]const []const u8 {
        var entries = std.StringHashMap(void).init(self.allocator);
        defer entries.deinit();

        var whiteouts = std.StringHashMap(void).init(self.allocator);
        defer whiteouts.deinit();

        // Collect entries from all layers
        for (self.layers.items) |layer| {
            // Skip process layers with pid > as_of_pid
            if (layer.layer_type == .process_files) {
                if (layer.pid) |pid| {
                    if (pid > as_of_pid) continue;
                }
            }

            var full_path_buf: [4096]u8 = undefined;
            const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ layer.path, path }) catch continue;

            var dir = std.fs.openDirAbsolute(full_path, .{ .iterate = true }) catch continue;
            defer dir.close();

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                // Check for whiteout
                if (whiteout.isWhiteoutName(entry.name)) {
                    const real_name = whiteout.getOriginalName(entry.name);
                    try whiteouts.put(real_name, {});
                } else if (!whiteouts.contains(entry.name)) {
                    try entries.put(entry.name, {});
                }
            }
        }

        // Convert to slice
        var result = std.ArrayList([]const u8).init(self.allocator);
        var iter = entries.keyIterator();
        while (iter.next()) |key| {
            try result.append(try self.allocator.dupe(u8, key.*));
        }

        return result.toOwnedSlice();
    }
};

test "OverlayState basic" {
    const allocator = std.testing.allocator;

    const sources = [_]struct { dst: []const u8, priority: i32, source: []const u8 }{
        .{ .dst = "/", .priority = 0, .source = "/tmp" },
    };
    const parents = [_][]const u8{};

    var overlay_state = try OverlayState.init(allocator, &sources, &parents);
    defer overlay_state.deinit();

    try std.testing.expectEqual(@as(usize, 1), overlay_state.layers.items.len);
}
