//! Trace buffer collection from managed processes
//!
//! Periodically scans the traces directory, reads data from trace files,
//! and uses hole punching to reclaim space.

const std = @import("std");
const linux = @import("../util/linux.zig");

/// Minimum bytes to leave unread at end of active trace file
const SAFETY_MARGIN: u64 = 1024 * 1024; // 1MB

/// Trace file state
const TraceFile = struct {
    path: []const u8,
    host_pid: std.os.linux.pid_t,
    read_offset: u64 = 0,
    finalized: bool = false,
};

/// Collector state
pub const Collector = struct {
    allocator: std.mem.Allocator,
    traces_dir: []const u8,
    trace_files: std.AutoHashMap(std.os.linux.pid_t, TraceFile),
    merged_events: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, traces_dir: []const u8) !Collector {
        return .{
            .allocator = allocator,
            .traces_dir = traces_dir,
            .trace_files = std.AutoHashMap(std.os.linux.pid_t, TraceFile).init(allocator),
            .merged_events = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Collector) void {
        var it = self.trace_files.valueIterator();
        while (it.next()) |tf| {
            self.allocator.free(tf.path);
        }
        self.trace_files.deinit();
        self.merged_events.deinit();
    }

    /// Scan for and collect trace data
    pub fn collect(self: *Collector) !void {
        // Scan directory for new trace files
        var dir = std.fs.openDirAbsolute(self.traces_dir, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            const pid = std.fmt.parseInt(std.os.linux.pid_t, entry.name, 10) catch continue;

            if (!self.trace_files.contains(pid)) {
                const path = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/{s}",
                    .{ self.traces_dir, entry.name },
                );
                try self.trace_files.put(pid, .{
                    .path = path,
                    .host_pid = pid,
                });
            }
        }

        // Collect from each trace file
        var to_remove = std.ArrayList(std.os.linux.pid_t).init(self.allocator);
        defer to_remove.deinit();

        var vit = self.trace_files.iterator();
        while (vit.next()) |entry| {
            const tf = entry.value_ptr;
            const still_active = try self.collectFromFile(tf);
            if (!still_active and tf.finalized) {
                try to_remove.append(entry.key_ptr.*);
            }
        }

        // Remove finalized and collected files
        for (to_remove.items) |pid| {
            if (self.trace_files.fetchRemove(pid)) |kv| {
                // Delete the trace file
                std.fs.deleteFileAbsolute(kv.value.path) catch {};
                self.allocator.free(kv.value.path);
            }
        }
    }

    /// Collect data from a single trace file
    fn collectFromFile(self: *Collector, tf: *TraceFile) !bool {
        const file = std.fs.openFileAbsolute(tf.path, .{}) catch return false;
        defer file.close();

        const stat = try file.stat();
        const file_size = stat.size;

        // Check if process is still alive
        const is_alive = std.os.linux.kill(tf.host_pid, 0) == 0;

        // Determine how much to read
        const read_limit: u64 = if (is_alive)
            if (file_size > SAFETY_MARGIN + tf.read_offset)
                file_size - SAFETY_MARGIN
            else
                tf.read_offset
        else
            file_size;

        if (read_limit > tf.read_offset) {
            const to_read = read_limit - tf.read_offset;

            // Read the data
            try file.seekTo(tf.read_offset);
            var buffer = try self.allocator.alloc(u8, @intCast(to_read));
            defer self.allocator.free(buffer);

            const bytes_read = try file.readAll(buffer);
            if (bytes_read > 0) {
                // Add to merged events
                try self.merged_events.appendSlice(buffer[0..bytes_read]);

                // Punch hole in the file to reclaim space
                const pages_to_punch = (bytes_read / 4096) * 4096;
                if (pages_to_punch > 0) {
                    linux.punchHole(
                        file.handle,
                        @intCast(tf.read_offset),
                        @intCast(pages_to_punch),
                    ) catch {};
                }

                tf.read_offset += bytes_read;
            }
        }

        return is_alive;
    }

    /// Finalize collection for a specific process
    pub fn finalizeProcess(self: *Collector, host_pid: std.os.linux.pid_t) !void {
        if (self.trace_files.getPtr(host_pid)) |tf| {
            tf.finalized = true;
            // Read remaining data
            _ = try self.collectFromFile(tf);
        }
    }

    /// Final collection - read all remaining data
    pub fn collectFinal(self: *Collector) !void {
        var vit = self.trace_files.valueIterator();
        while (vit.next()) |tf| {
            tf.finalized = true;
            _ = try self.collectFromFile(tf);
        }
    }

    /// Get collected event data
    pub fn getEvents(self: *Collector) []const u8 {
        return self.merged_events.items;
    }

    /// Clear collected events
    pub fn clearEvents(self: *Collector) void {
        self.merged_events.clearRetainingCapacity();
    }
};

test "Collector initialization" {
    const allocator = std.testing.allocator;

    var collector = try Collector.init(allocator, "/tmp/test-traces");
    defer collector.deinit();

    try std.testing.expectEqual(@as(usize, 0), collector.trace_files.count());
}
