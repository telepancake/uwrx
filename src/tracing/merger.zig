//! Trace merging and compression
//!
//! Merges events from multiple trace buffers, sorts by timestamp,
//! and compresses the final output.

const std = @import("std");
const deflate = @import("../util/deflate.zig");
const events = @import("events.zig");
const perfetto = @import("perfetto.zig");

/// Trace event with metadata for sorting
const TimestampedEvent = struct {
    timestamp: i64,
    process_id: u32,
    data: []const u8,

    fn lessThan(_: void, a: TimestampedEvent, b: TimestampedEvent) bool {
        if (a.timestamp != b.timestamp) {
            return a.timestamp < b.timestamp;
        }
        return a.process_id < b.process_id;
    }
};

/// Trace merger
pub const Merger = struct {
    allocator: std.mem.Allocator,
    events_list: std.ArrayList(TimestampedEvent),
    process_descriptors: std.AutoHashMap(u32, []u8),

    pub fn init(allocator: std.mem.Allocator) Merger {
        return .{
            .allocator = allocator,
            .events_list = std.ArrayList(TimestampedEvent).init(allocator),
            .process_descriptors = std.AutoHashMap(u32, []u8).init(allocator),
        };
    }

    pub fn deinit(self: *Merger) void {
        for (self.events_list.items) |event| {
            self.allocator.free(event.data);
        }
        self.events_list.deinit();

        var it = self.process_descriptors.valueIterator();
        while (it.next()) |desc| {
            self.allocator.free(desc.*);
        }
        self.process_descriptors.deinit();
    }

    /// Add a process descriptor
    pub fn addProcess(self: *Merger, pid: u32, name: []const u8) !void {
        if (self.process_descriptors.contains(pid)) {
            return; // Already have this process
        }

        const desc = try perfetto.createProcessDescriptor(self.allocator, pid, name);
        try self.process_descriptors.put(pid, desc);
    }

    /// Add raw event data with timestamp
    pub fn addEvent(self: *Merger, timestamp: i64, process_id: u32, data: []const u8) !void {
        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);

        try self.events_list.append(.{
            .timestamp = timestamp,
            .process_id = process_id,
            .data = data_copy,
        });
    }

    /// Merge and sort all events, return compressed trace
    pub fn merge(self: *Merger) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        // Write process descriptors first
        var desc_it = self.process_descriptors.valueIterator();
        while (desc_it.next()) |desc| {
            try result.appendSlice(desc.*);
        }

        // Sort events by timestamp
        std.mem.sort(TimestampedEvent, self.events_list.items, {}, TimestampedEvent.lessThan);

        // Write sorted events
        for (self.events_list.items) |event| {
            try result.appendSlice(event.data);
        }

        // Compress the result
        return deflate.compress(self.allocator, result.items);
    }

    /// Clear all events (but keep process descriptors)
    pub fn clearEvents(self: *Merger) void {
        for (self.events_list.items) |event| {
            self.allocator.free(event.data);
        }
        self.events_list.clearRetainingCapacity();
    }
};

/// Parse raw trace data into events
pub fn parseTraceData(allocator: std.mem.Allocator, data: []const u8) !std.ArrayList(TimestampedEvent) {
    var result = std.ArrayList(TimestampedEvent).init(allocator);
    errdefer {
        for (result.items) |event| {
            allocator.free(event.data);
        }
        result.deinit();
    }

    // Simple parsing - in reality would parse protobuf
    var offset: usize = 0;
    while (offset < data.len) {
        // Find event boundary (simplified)
        const remaining = data.len - offset;
        if (remaining < 4) break;

        // Read length prefix (assuming length-delimited format)
        const len = std.mem.readInt(u32, data[offset..][0..4], .little);
        offset += 4;

        if (offset + len > data.len) break;

        const event_data = try allocator.dupe(u8, data[offset .. offset + len]);
        try result.append(.{
            .timestamp = 0, // Would extract from protobuf
            .process_id = 0, // Would extract from protobuf
            .data = event_data,
        });

        offset += len;
    }

    return result;
}

test "Merger basic operations" {
    const allocator = std.testing.allocator;

    var merger = Merger.init(allocator);
    defer merger.deinit();

    try merger.addProcess(2, "test-process");

    try merger.addEvent(100, 2, "event1");
    try merger.addEvent(50, 2, "event2");
    try merger.addEvent(75, 2, "event3");

    const merged = try merger.merge();
    defer allocator.free(merged);

    try std.testing.expect(merged.len > 0);
}
