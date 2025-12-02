//! Replay logic for traces
//!
//! Handles replaying recorded network responses and trace events.

const std = @import("std");
const storage = @import("../tracing/storage.zig");

/// Replay state
pub const ReplayState = struct {
    allocator: std.mem.Allocator,
    /// Path to trace being replayed
    trace_path: []const u8,
    /// Network response cache
    network_cache: std.StringHashMap(CachedResponse),
    /// File cache
    file_cache: std.StringHashMap([]const u8),
    /// Process exit statuses
    exit_statuses: std.AutoHashMap(u32, u32),
    /// Process stdout
    stdout_cache: std.AutoHashMap(u32, []const u8),
    /// Process stderr
    stderr_cache: std.AutoHashMap(u32, []const u8),

    pub fn init(allocator: std.mem.Allocator, trace_path: []const u8) !ReplayState {
        return .{
            .allocator = allocator,
            .trace_path = try allocator.dupe(u8, trace_path),
            .network_cache = std.StringHashMap(CachedResponse).init(allocator),
            .file_cache = std.StringHashMap([]const u8).init(allocator),
            .exit_statuses = std.AutoHashMap(u32, u32).init(allocator),
            .stdout_cache = std.AutoHashMap(u32, []const u8).init(allocator),
            .stderr_cache = std.AutoHashMap(u32, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *ReplayState) void {
        self.allocator.free(self.trace_path);

        var net_it = self.network_cache.valueIterator();
        while (net_it.next()) |resp| {
            self.allocator.free(resp.body);
        }
        self.network_cache.deinit();

        var file_it = self.file_cache.valueIterator();
        while (file_it.next()) |content| {
            self.allocator.free(content.*);
        }
        self.file_cache.deinit();

        self.exit_statuses.deinit();

        var stdout_it = self.stdout_cache.valueIterator();
        while (stdout_it.next()) |data| {
            self.allocator.free(data.*);
        }
        self.stdout_cache.deinit();

        var stderr_it = self.stderr_cache.valueIterator();
        while (stderr_it.next()) |data| {
            self.allocator.free(data.*);
        }
        self.stderr_cache.deinit();
    }

    /// Load replay data from trace
    pub fn load(self: *ReplayState) !void {
        // Load network cache from net/ directory
        try self.loadNetworkCache();

        // Load file cache from files/ directories
        try self.loadFileCache();

        // Parse trace for exit statuses and output
        try self.loadTraceEvents();
    }

    fn loadNetworkCache(self: *ReplayState) !void {
        const net_dir = try std.fmt.allocPrint(self.allocator, "{s}/net", .{self.trace_path});
        defer self.allocator.free(net_dir);

        var dir = std.fs.openDirAbsolute(net_dir, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            // Each subdirectory is a domain
            const domain = entry.name;

            // Load cached responses for this domain
            const domain_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ net_dir, domain });
            defer self.allocator.free(domain_dir);

            try self.loadDomainCache(domain_dir, domain);
        }
    }

    fn loadDomainCache(self: *ReplayState, dir_path: []const u8, domain: []const u8) !void {
        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            // Skip metadata files
            if (std.mem.eql(u8, entry.name, "cert.pem")) continue;
            if (std.mem.eql(u8, entry.name, "ip4.txt")) continue;
            if (std.mem.eql(u8, entry.name, "ip6.txt")) continue;

            const file_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir_path, entry.name });
            defer self.allocator.free(file_path);

            const content = std.fs.cwd().readFileAlloc(self.allocator, file_path, 100 * 1024 * 1024) catch continue;

            const cache_key = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ domain, entry.name });
            try self.network_cache.put(cache_key, .{
                .body = content,
                .status = 200,
            });
        }
    }

    fn loadFileCache(self: *ReplayState) !void {
        const files_dir = try std.fmt.allocPrint(self.allocator, "{s}/files", .{self.trace_path});
        defer self.allocator.free(files_dir);

        try self.loadFilesRecursive(files_dir, "");
    }

    fn loadFilesRecursive(self: *ReplayState, base_dir: []const u8, rel_path: []const u8) !void {
        const full_dir = if (rel_path.len > 0)
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_dir, rel_path })
        else
            try self.allocator.dupe(u8, base_dir);
        defer self.allocator.free(full_dir);

        var dir = std.fs.openDirAbsolute(full_dir, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const entry_path = if (rel_path.len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ rel_path, entry.name })
            else
                try std.fmt.allocPrint(self.allocator, "/{s}", .{entry.name});

            if (entry.kind == .directory) {
                try self.loadFilesRecursive(base_dir, entry_path);
                self.allocator.free(entry_path);
            } else {
                const file_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_dir, entry_path });
                defer self.allocator.free(file_path);

                const content = std.fs.cwd().readFileAlloc(self.allocator, file_path, 100 * 1024 * 1024) catch {
                    self.allocator.free(entry_path);
                    continue;
                };

                try self.file_cache.put(entry_path, content);
            }
        }
    }

    fn loadTraceEvents(self: *ReplayState) !void {
        // Load and parse trace to extract exit statuses and output
        const trace_path = try std.fmt.allocPrint(self.allocator, "{s}/perfetto", .{self.trace_path});
        defer self.allocator.free(trace_path);

        const trace_data = storage.loadTrace(self.allocator, trace_path) catch return;
        defer self.allocator.free(trace_data);

        // Parse trace data (simplified - would parse protobuf in reality)
        _ = trace_data;
    }

    /// Get cached network response
    pub fn getNetworkResponse(self: *ReplayState, key: []const u8) ?CachedResponse {
        return self.network_cache.get(key);
    }

    /// Get cached file content
    pub fn getFileContent(self: *ReplayState, path: []const u8) ?[]const u8 {
        return self.file_cache.get(path);
    }

    /// Get exit status for process
    pub fn getExitStatus(self: *ReplayState, pid: u32) ?u32 {
        return self.exit_statuses.get(pid);
    }

    /// Get stdout for process
    pub fn getStdout(self: *ReplayState, pid: u32) ?[]const u8 {
        return self.stdout_cache.get(pid);
    }

    /// Get stderr for process
    pub fn getStderr(self: *ReplayState, pid: u32) ?[]const u8 {
        return self.stderr_cache.get(pid);
    }
};

/// Cached network response
pub const CachedResponse = struct {
    body: []const u8,
    status: u16,
    headers: ?[]const u8 = null,
};

test "ReplayState initialization" {
    const allocator = std.testing.allocator;

    var state = try ReplayState.init(allocator, "/tmp/test-trace");
    defer state.deinit();

    try std.testing.expectEqualStrings("/tmp/test-trace", state.trace_path);
}
