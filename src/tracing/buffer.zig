//! Trace buffer management
//!
//! Manages mmap'd buffers for high-performance trace writing
//! with minimal syscall overhead.

const std = @import("std");
const linux = @import("../util/linux.zig");

/// Buffer window size (1 MB)
pub const BUFFER_SIZE: usize = 1024 * 1024;

/// Maximum event size
pub const MAX_EVENT_SIZE: usize = 64 * 1024;

/// Page size
const PAGE_SIZE: usize = 4096;

/// Trace buffer for a single process
pub const TraceBuffer = struct {
    allocator: std.mem.Allocator,
    /// Path to the trace file
    path: []u8,
    /// File descriptor
    fd: std.os.linux.fd_t,
    /// Current mmap'd region
    map_base: ?[*]u8,
    /// Size of mapped region
    map_size: usize,
    /// Offset in file where map starts
    map_offset: u64,
    /// Current write position within the map
    write_pos: usize,
    /// Total bytes written to file
    total_written: u64,

    pub fn init(allocator: std.mem.Allocator, traces_dir: []const u8, pid: u32) !TraceBuffer {
        // Create trace file path
        const path = try std.fmt.allocPrint(allocator, "{s}/{d}", .{ traces_dir, pid });
        errdefer allocator.free(path);

        // Open/create trace file
        const fd = try std.posix.open(
            path,
            .{
                .ACCMODE = .RDWR,
                .CREAT = true,
                .TRUNC = true,
            },
            0o644,
        );
        errdefer _ = std.os.linux.close(fd);

        // Extend file to initial size
        try std.posix.ftruncate(fd, BUFFER_SIZE);

        // Map first window
        const map_result = std.os.linux.mmap(
            null,
            BUFFER_SIZE,
            std.os.linux.PROT.READ | std.os.linux.PROT.WRITE,
            .{ .TYPE = .SHARED, .POPULATE = true },
            fd,
            0,
        );

        if (map_result == ~@as(usize, 0)) {
            return error.MmapFailed;
        }

        return .{
            .allocator = allocator,
            .path = path,
            .fd = fd,
            .map_base = @ptrFromInt(map_result),
            .map_size = BUFFER_SIZE,
            .map_offset = 0,
            .write_pos = 0,
            .total_written = 0,
        };
    }

    pub fn deinit(self: *TraceBuffer) void {
        if (self.map_base) |base| {
            _ = std.os.linux.munmap(base, self.map_size);
        }
        _ = std.os.linux.close(self.fd);
        self.allocator.free(self.path);
    }

    /// Write data to the trace buffer
    pub fn write(self: *TraceBuffer, data: []const u8) !void {
        if (data.len > MAX_EVENT_SIZE) {
            return error.EventTooLarge;
        }

        // Check if we need to advance the window
        if (self.write_pos + data.len > BUFFER_SIZE - MAX_EVENT_SIZE) {
            try self.advanceWindow();
        }

        // Write to buffer
        if (self.map_base) |base| {
            @memcpy(base[self.write_pos .. self.write_pos + data.len], data);
            self.write_pos += data.len;
            self.total_written += data.len;
        } else {
            return error.NoBuffer;
        }
    }

    /// Advance the mmap window
    fn advanceWindow(self: *TraceBuffer) !void {
        const advance_bytes = BUFFER_SIZE - MAX_EVENT_SIZE;
        const advance_pages = (advance_bytes / PAGE_SIZE) * PAGE_SIZE;

        // Unmap current region
        if (self.map_base) |base| {
            _ = std.os.linux.munmap(base, self.map_size);
        }

        // Update file offset
        self.map_offset += advance_pages;

        // Extend file if needed
        const new_end = self.map_offset + BUFFER_SIZE;
        const stat = try std.posix.fstat(self.fd);
        if (new_end > @as(u64, @intCast(stat.size))) {
            try std.posix.ftruncate(self.fd, @intCast(new_end));
        }

        // Map new window
        const map_result = std.os.linux.mmap(
            null,
            BUFFER_SIZE,
            std.os.linux.PROT.READ | std.os.linux.PROT.WRITE,
            .{ .TYPE = .SHARED, .POPULATE = true },
            self.fd,
            @intCast(self.map_offset),
        );

        if (map_result == ~@as(usize, 0)) {
            self.map_base = null;
            return error.MmapFailed;
        }

        self.map_base = @ptrFromInt(map_result);
        self.write_pos = self.write_pos - advance_pages;
    }

    /// Flush any buffered data (msync)
    pub fn flush(self: *TraceBuffer) !void {
        if (self.map_base) |base| {
            const result = std.os.linux.msync(base, self.map_size, std.os.linux.MSF.SYNC);
            if (result != 0) {
                return error.MsyncFailed;
            }
        }
    }

    /// Get current file position
    pub fn position(self: *TraceBuffer) u64 {
        return self.map_offset + self.write_pos;
    }
};

test "TraceBuffer init and write" {
    const allocator = std.testing.allocator;

    // Create temp directory
    const tmp_dir = "/tmp/uwrx-test-buffer";
    std.fs.makeDirAbsolute(tmp_dir) catch {};
    defer std.fs.deleteTreeAbsolute(tmp_dir) catch {};

    var buf = try TraceBuffer.init(allocator, tmp_dir, 12345);
    defer buf.deinit();

    // Write some data
    try buf.write("Hello, trace!");
    try std.testing.expectEqual(@as(usize, 13), buf.write_pos);

    try buf.flush();
}
