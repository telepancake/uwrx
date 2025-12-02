//! File modification metadata tracking
//!
//! Tracks which process modified which files for partial rebuild support.
//! Directory structure:
//!   files/<path>         - first written version of each file
//!   files-<pid>/<path>   - overwrite by process <pid>

const std = @import("std");

/// File version info
pub const FileVersion = struct {
    /// Process that created this version
    pid: u32,
    /// Path to the actual file
    actual_path: []const u8,
    /// Whether this is a whiteout (deletion)
    is_whiteout: bool,
};

/// Metadata tracker for file modifications
pub const MetaTracker = struct {
    allocator: std.mem.Allocator,
    /// Base files directory
    files_dir: []const u8,
    /// Known files and their first-write status
    known_files: std.StringHashMap(u32), // path -> first writer pid
    /// File versions per process
    process_writes: std.AutoHashMap(u32, std.StringHashMap(void)),

    pub fn init(allocator: std.mem.Allocator, files_dir: []const u8) MetaTracker {
        return .{
            .allocator = allocator,
            .files_dir = files_dir,
            .known_files = std.StringHashMap(u32).init(allocator),
            .process_writes = std.AutoHashMap(u32, std.StringHashMap(void)).init(allocator),
        };
    }

    pub fn deinit(self: *MetaTracker) void {
        self.known_files.deinit();

        var it = self.process_writes.valueIterator();
        while (it.next()) |writes| {
            writes.deinit();
        }
        self.process_writes.deinit();
    }

    /// Get the path to write a file to
    pub fn getWritePath(self: *MetaTracker, path: []const u8, pid: u32) ![]const u8 {
        if (self.known_files.get(path)) |first_writer| {
            // File already exists, write to process-specific directory
            _ = first_writer;
            return std.fmt.allocPrint(
                self.allocator,
                "{s}-{d}{s}",
                .{ self.files_dir, pid, path },
            );
        } else {
            // First write, use base files directory
            return std.fmt.allocPrint(
                self.allocator,
                "{s}{s}",
                .{ self.files_dir, path },
            );
        }
    }

    /// Record a file modification
    pub fn recordModification(self: *MetaTracker, path: []const u8, pid: u32) !void {
        // Track first writer
        const gop = try self.known_files.getOrPut(path);
        if (!gop.found_existing) {
            gop.value_ptr.* = pid;
        }

        // Track in process writes
        const writes_gop = try self.process_writes.getOrPut(pid);
        if (!writes_gop.found_existing) {
            writes_gop.value_ptr.* = std.StringHashMap(void).init(self.allocator);
        }
        try writes_gop.value_ptr.put(path, {});
    }

    /// Resolve which file version a process would see
    pub fn resolveFile(self: *MetaTracker, path: []const u8, as_of_pid: u32) ?FileVersion {
        // Check process-specific directories in order (highest pid <= as_of_pid)
        var best_pid: u32 = 0;

        var iter = self.process_writes.iterator();
        while (iter.next()) |entry| {
            const pid = entry.key_ptr.*;
            if (pid <= as_of_pid and pid > best_pid) {
                if (entry.value_ptr.contains(path)) {
                    best_pid = pid;
                }
            }
        }

        if (best_pid > 0) {
            return .{
                .pid = best_pid,
                .actual_path = path, // Would construct full path
                .is_whiteout = false,
            };
        }

        // Check base files
        if (self.known_files.get(path)) |first_writer| {
            if (first_writer <= as_of_pid) {
                return .{
                    .pid = first_writer,
                    .actual_path = path,
                    .is_whiteout = false,
                };
            }
        }

        return null;
    }

    /// Get all files written by a process
    pub fn getProcessFiles(self: *MetaTracker, pid: u32) ?std.StringHashMap(void) {
        return self.process_writes.get(pid);
    }

    /// Get all known files
    pub fn getAllFiles(self: *MetaTracker) []const []const u8 {
        var result = std.ArrayList([]const u8).init(self.allocator);
        var iter = self.known_files.keyIterator();
        while (iter.next()) |key| {
            result.append(key.*) catch continue;
        }
        return result.toOwnedSlice() catch &.{};
    }

    /// Create directory structure for a path
    pub fn ensureDirectory(self: *MetaTracker, path: []const u8, pid: u32) !void {
        const full_path = try self.getWritePath(path, pid);
        defer self.allocator.free(full_path);

        if (std.fs.path.dirname(full_path)) |parent| {
            try std.fs.makeDirAbsolute(parent);
        }
    }
};

/// Scan a trace directory for file modifications
pub fn scanTraceFiles(allocator: std.mem.Allocator, trace_dir: []const u8) !MetaTracker {
    var tracker = MetaTracker.init(allocator, trace_dir);
    errdefer tracker.deinit();

    // Scan base files directory
    const files_dir = try std.fmt.allocPrint(allocator, "{s}/files", .{trace_dir});
    defer allocator.free(files_dir);

    try scanDirectory(&tracker, files_dir, "", 1);

    // Scan process-specific directories
    var dir = std.fs.openDirAbsolute(trace_dir, .{ .iterate = true }) catch return tracker;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "files-")) continue;

        const pid_str = entry.name[6..];
        const pid = std.fmt.parseInt(u32, pid_str, 10) catch continue;

        const process_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ trace_dir, entry.name });
        defer allocator.free(process_dir);

        try scanDirectory(&tracker, process_dir, "", pid);
    }

    return tracker;
}

fn scanDirectory(tracker: *MetaTracker, base_dir: []const u8, rel_path: []const u8, pid: u32) !void {
    const full_dir = if (rel_path.len > 0)
        try std.fmt.allocPrint(tracker.allocator, "{s}/{s}", .{ base_dir, rel_path })
    else
        try tracker.allocator.dupe(u8, base_dir);
    defer tracker.allocator.free(full_dir);

    var dir = std.fs.openDirAbsolute(full_dir, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const entry_path = if (rel_path.len > 0)
            try std.fmt.allocPrint(tracker.allocator, "{s}/{s}", .{ rel_path, entry.name })
        else
            try std.fmt.allocPrint(tracker.allocator, "/{s}", .{entry.name});
        defer tracker.allocator.free(entry_path);

        if (entry.kind == .directory) {
            try scanDirectory(tracker, base_dir, entry_path, pid);
        } else {
            try tracker.recordModification(entry_path, pid);
        }
    }
}

test "MetaTracker basic" {
    const allocator = std.testing.allocator;

    var tracker = MetaTracker.init(allocator, "/tmp/files");
    defer tracker.deinit();

    try tracker.recordModification("/foo.txt", 2);
    try tracker.recordModification("/bar.txt", 3);
    try tracker.recordModification("/foo.txt", 3); // Overwrite

    const v1 = tracker.resolveFile("/foo.txt", 2);
    try std.testing.expect(v1 != null);
    try std.testing.expectEqual(@as(u32, 2), v1.?.pid);

    const v2 = tracker.resolveFile("/foo.txt", 4);
    try std.testing.expect(v2 != null);
    try std.testing.expectEqual(@as(u32, 3), v2.?.pid);
}
