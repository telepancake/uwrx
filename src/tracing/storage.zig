//! Trace storage management
//!
//! Manages the directory structure for traces:
//! build/<step>/<attempt>/

const std = @import("std");
const deflate = @import("../util/deflate.zig");

/// Trace storage manager
pub const Storage = struct {
    allocator: std.mem.Allocator,
    build_dir: []const u8,
    step: []const u8,
    attempt: u32,
    attempt_dir: []u8,

    pub fn init(allocator: std.mem.Allocator, build_dir: []const u8, step: ?[]const u8) !Storage {
        // Determine step name
        const actual_step = step orelse try findNextStep(allocator, build_dir);
        defer if (step == null) allocator.free(actual_step);

        const step_owned = try allocator.dupe(u8, actual_step);
        errdefer allocator.free(step_owned);

        // Create step directory
        const step_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ build_dir, step_owned });
        defer allocator.free(step_dir);

        std.fs.makeDirAbsolute(build_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.makeDirAbsolute(step_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        // Find next attempt number
        const attempt = try findNextAttempt(allocator, step_dir);

        // Create attempt directory
        const attempt_dir = try std.fmt.allocPrint(allocator, "{s}/{d}", .{ step_dir, attempt });
        errdefer allocator.free(attempt_dir);

        std.fs.makeDirAbsolute(attempt_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return .{
            .allocator = allocator,
            .build_dir = build_dir,
            .step = step_owned,
            .attempt = attempt,
            .attempt_dir = attempt_dir,
        };
    }

    pub fn deinit(self: *Storage) void {
        self.allocator.free(self.step);
        self.allocator.free(self.attempt_dir);
    }

    /// Write command to step directory
    pub fn writeCommand(self: *Storage, command: []const []const u8) !void {
        const step_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.build_dir, self.step });
        defer self.allocator.free(step_dir);

        const cmd_path = try std.fmt.allocPrint(self.allocator, "{s}/cmd", .{step_dir});
        defer self.allocator.free(cmd_path);

        const file = try std.fs.createFileAbsolute(cmd_path, .{});
        defer file.close();

        for (command) |arg| {
            try file.writeAll(arg);
            try file.writeAll("\n");
        }
    }

    /// Write options to step directory
    pub fn writeOptions(self: *Storage, options_str: []const u8) !void {
        const step_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.build_dir, self.step });
        defer self.allocator.free(step_dir);

        const opts_path = try std.fmt.allocPrint(self.allocator, "{s}/options", .{step_dir});
        defer self.allocator.free(opts_path);

        const file = try std.fs.createFileAbsolute(opts_path, .{});
        defer file.close();

        try file.writeAll(options_str);
    }

    /// Write compressed trace data
    pub fn writeTrace(self: *Storage, data: []const u8) !void {
        const trace_path = try std.fmt.allocPrint(self.allocator, "{s}/perfetto", .{self.attempt_dir});
        defer self.allocator.free(trace_path);

        const file = try std.fs.createFileAbsolute(trace_path, .{});
        defer file.close();

        try file.writeAll(data);
    }

    /// Write CA certificate
    pub fn writeCaCert(self: *Storage, cert: []const u8) !void {
        const cert_path = try std.fmt.allocPrint(self.allocator, "{s}/ca.pem", .{self.attempt_dir});
        defer self.allocator.free(cert_path);

        const file = try std.fs.createFileAbsolute(cert_path, .{});
        defer file.close();

        try file.writeAll(cert);
    }

    /// Write PRNG seed
    pub fn writeSeed(self: *Storage, seed: u64) !void {
        const seed_path = try std.fmt.allocPrint(self.allocator, "{s}/seed.txt", .{self.attempt_dir});
        defer self.allocator.free(seed_path);

        const file = try std.fs.createFileAbsolute(seed_path, .{});
        defer file.close();

        var buf: [16]u8 = undefined;
        const hex = std.fmt.bufPrint(&buf, "{x:0>16}", .{seed}) catch unreachable;
        try file.writeAll(hex);
    }

    /// Write source specifications
    pub fn writeSources(self: *Storage, sources: []const SourceEntry) !void {
        const sources_path = try std.fmt.allocPrint(self.allocator, "{s}/sources.txt", .{self.attempt_dir});
        defer self.allocator.free(sources_path);

        const file = try std.fs.createFileAbsolute(sources_path, .{});
        defer file.close();

        for (sources) |source| {
            try file.writeAll(source.dst);
            try file.writeAll("\t");
            var buf: [16]u8 = undefined;
            const priority_str = std.fmt.bufPrint(&buf, "{d}", .{source.priority}) catch unreachable;
            try file.writeAll(priority_str);
            try file.writeAll("\t");
            try file.writeAll(source.source_type);
            try file.writeAll("\t");
            try file.writeAll(source.source_spec);
            try file.writeAll("\n");
        }
    }

    /// Create files directory
    pub fn createFilesDir(self: *Storage) ![]u8 {
        const files_dir = try std.fmt.allocPrint(self.allocator, "{s}/files", .{self.attempt_dir});
        errdefer self.allocator.free(files_dir);

        std.fs.makeDirAbsolute(files_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return files_dir;
    }

    /// Create per-process files directory
    pub fn createProcessFilesDir(self: *Storage, pid: u32) ![]u8 {
        const dir_path = try std.fmt.allocPrint(self.allocator, "{s}/files-{d}", .{ self.attempt_dir, pid });
        errdefer self.allocator.free(dir_path);

        std.fs.makeDirAbsolute(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return dir_path;
    }

    /// Create parent symlink
    pub fn createParentLink(self: *Storage, index: u32, target: []const u8) !void {
        const link_path = try std.fmt.allocPrint(self.allocator, "{s}/parent/{d}", .{ self.attempt_dir, index });
        defer self.allocator.free(link_path);

        const parent_dir = try std.fmt.allocPrint(self.allocator, "{s}/parent", .{self.attempt_dir});
        defer self.allocator.free(parent_dir);

        std.fs.makeDirAbsolute(parent_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.posix.symlink(target, link_path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                try std.fs.deleteFileAbsolute(link_path);
                try std.posix.symlink(target, link_path);
            },
            else => return err,
        };
    }

    /// Create replay symlink
    pub fn createReplayLink(self: *Storage, target: []const u8) !void {
        const link_path = try std.fmt.allocPrint(self.allocator, "{s}/replay", .{self.attempt_dir});
        defer self.allocator.free(link_path);

        std.posix.symlink(target, link_path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                try std.fs.deleteFileAbsolute(link_path);
                try std.posix.symlink(target, link_path);
            },
            else => return err,
        };
    }

    /// Get path within attempt directory
    pub fn getPath(self: *Storage, sub_path: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.attempt_dir, sub_path });
    }
};

/// Source entry for sources.txt
pub const SourceEntry = struct {
    dst: []const u8,
    priority: i32,
    source_type: []const u8,
    source_spec: []const u8,
};

/// Find the next step number
fn findNextStep(allocator: std.mem.Allocator, build_dir: []const u8) ![]u8 {
    var max_step: i32 = -10; // Allow for negative steps

    var dir = std.fs.openDirAbsolute(build_dir, .{ .iterate = true }) catch {
        return std.fmt.allocPrint(allocator, "0", .{});
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        const step_num = std.fmt.parseInt(i32, entry.name, 10) catch continue;
        if (step_num > max_step) {
            max_step = step_num;
        }
    }

    const next_step = if (max_step < 0) 0 else max_step + 10;
    return std.fmt.allocPrint(allocator, "{d}", .{next_step});
}

/// Find the next attempt number
fn findNextAttempt(allocator: std.mem.Allocator, step_dir: []const u8) !u32 {
    _ = allocator;
    var max_attempt: u32 = 0;

    var dir = std.fs.openDirAbsolute(step_dir, .{ .iterate = true }) catch {
        return 0;
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        const attempt_num = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        if (attempt_num >= max_attempt) {
            max_attempt = attempt_num + 1;
        }
    }

    return max_attempt;
}

/// Load trace from storage
pub fn loadTrace(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const stat = try file.stat();
    const compressed = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(compressed);

    _ = try file.readAll(compressed);

    return deflate.decompress(allocator, compressed);
}

test "findNextStep" {
    const allocator = std.testing.allocator;
    const step = try findNextStep(allocator, "/nonexistent");
    defer allocator.free(step);
    try std.testing.expectEqualStrings("0", step);
}
