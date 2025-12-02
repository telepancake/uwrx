//! Cache hit detection
//!
//! Determines if a process can be skipped by comparing its inputs
//! to the previous run.

const std = @import("std");
const meta = @import("../filesystem/meta.zig");

/// Process inputs from replay trace
pub const ProcessInputs = struct {
    allocator: std.mem.Allocator,
    /// Files read by the process
    read_files: std.StringHashMap(FileVersion),
    /// Files written by the process
    write_files: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) ProcessInputs {
        return .{
            .allocator = allocator,
            .read_files = std.StringHashMap(FileVersion).init(allocator),
            .write_files = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *ProcessInputs) void {
        self.read_files.deinit();
        self.write_files.deinit();
    }
};

/// File version info
pub const FileVersion = struct {
    /// Hash of file contents
    hash: u64,
    /// Size of file
    size: u64,
    /// Which process created this version
    creator_pid: u32,
};

/// Cache state
pub const CacheState = struct {
    allocator: std.mem.Allocator,
    /// Per-process inputs from replay trace
    process_inputs: std.AutoHashMap(u32, ProcessInputs),
    /// Current file hashes
    current_hashes: std.StringHashMap(u64),

    pub fn init(allocator: std.mem.Allocator) CacheState {
        return .{
            .allocator = allocator,
            .process_inputs = std.AutoHashMap(u32, ProcessInputs).init(allocator),
            .current_hashes = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *CacheState) void {
        var it = self.process_inputs.valueIterator();
        while (it.next()) |inputs| {
            inputs.deinit();
        }
        self.process_inputs.deinit();
        self.current_hashes.deinit();
    }

    /// Load process inputs from replay trace
    pub fn loadFromReplay(self: *CacheState, trace_path: []const u8) !void {
        _ = trace_path;
        // Parse trace and extract file access patterns per process
        // This would read the perfetto trace and extract read/write events
    }

    /// Check if a process has a cache hit
    pub fn checkHit(self: *CacheState, pid: u32) bool {
        const inputs = self.process_inputs.get(pid) orelse return false;

        // Check all input files
        var it = inputs.read_files.iterator();
        while (it.next()) |entry| {
            const path = entry.key_ptr.*;
            const expected = entry.value_ptr.*;

            // Get current hash
            const current_hash = self.current_hashes.get(path) orelse {
                // File doesn't exist or not tracked
                return false;
            };

            if (current_hash != expected.hash) {
                return false;
            }
        }

        return true;
    }

    /// Record file read for current run
    pub fn recordRead(self: *CacheState, pid: u32, path: []const u8, hash: u64) !void {
        const gop = try self.process_inputs.getOrPut(pid);
        if (!gop.found_existing) {
            gop.value_ptr.* = ProcessInputs.init(self.allocator);
        }

        try gop.value_ptr.read_files.put(path, .{
            .hash = hash,
            .size = 0,
            .creator_pid = 0,
        });
    }

    /// Update current file hash
    pub fn updateHash(self: *CacheState, path: []const u8, hash: u64) !void {
        try self.current_hashes.put(path, hash);
    }
};

/// Hash file contents
pub fn hashFile(path: []const u8) !u64 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var hasher = std.hash.Wyhash.init(0);

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }

    return hasher.final();
}

test "CacheState basic" {
    const allocator = std.testing.allocator;

    var cache = CacheState.init(allocator);
    defer cache.deinit();

    // No inputs recorded, should not be a cache hit
    try std.testing.expect(!cache.checkHit(2));
}
