//! Perfetto trace format writer
//!
//! Implements the Perfetto/Chrome trace format for compatibility
//! with the Perfetto UI trace viewer.

const std = @import("std");
const events = @import("events.zig");

/// Perfetto trace packet types
pub const TracePacketType = enum(u8) {
    track_descriptor = 1,
    track_event = 2,
    clock_snapshot = 3,
    process_descriptor = 4,
    thread_descriptor = 5,
};

/// Track type for Perfetto
pub const TrackType = enum(u8) {
    process = 1,
    thread = 2,
    counter = 3,
};

/// Protobuf wire types
const WireType = enum(u3) {
    varint = 0,
    fixed64 = 1,
    length_delimited = 2,
    start_group = 3,
    end_group = 4,
    fixed32 = 5,
};

/// Simple protobuf encoder
pub const ProtobufEncoder = struct {
    buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) ProtobufEncoder {
        return .{
            .buffer = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *ProtobufEncoder) void {
        self.buffer.deinit();
    }

    pub fn toOwnedSlice(self: *ProtobufEncoder) ![]u8 {
        return self.buffer.toOwnedSlice();
    }

    pub fn reset(self: *ProtobufEncoder) void {
        self.buffer.clearRetainingCapacity();
    }

    /// Write a varint
    pub fn writeVarint(self: *ProtobufEncoder, value: u64) !void {
        var v = value;
        while (v >= 0x80) {
            try self.buffer.append(@truncate((v & 0x7F) | 0x80));
            v >>= 7;
        }
        try self.buffer.append(@truncate(v));
    }

    /// Write a signed varint (zigzag encoded)
    pub fn writeSignedVarint(self: *ProtobufEncoder, value: i64) !void {
        const encoded: u64 = @bitCast((value << 1) ^ (value >> 63));
        try self.writeVarint(encoded);
    }

    /// Write field tag
    pub fn writeTag(self: *ProtobufEncoder, field_number: u32, wire_type: WireType) !void {
        const tag = (@as(u64, field_number) << 3) | @intFromEnum(wire_type);
        try self.writeVarint(tag);
    }

    /// Write a string/bytes field
    pub fn writeBytes(self: *ProtobufEncoder, field_number: u32, data: []const u8) !void {
        try self.writeTag(field_number, .length_delimited);
        try self.writeVarint(data.len);
        try self.buffer.appendSlice(data);
    }

    /// Write a uint64 field
    pub fn writeUint64(self: *ProtobufEncoder, field_number: u32, value: u64) !void {
        try self.writeTag(field_number, .varint);
        try self.writeVarint(value);
    }

    /// Write a uint32 field
    pub fn writeUint32(self: *ProtobufEncoder, field_number: u32, value: u32) !void {
        try self.writeTag(field_number, .varint);
        try self.writeVarint(value);
    }

    /// Write an int64 field
    pub fn writeInt64(self: *ProtobufEncoder, field_number: u32, value: i64) !void {
        try self.writeTag(field_number, .varint);
        try self.writeSignedVarint(value);
    }

    /// Write a bool field
    pub fn writeBool(self: *ProtobufEncoder, field_number: u32, value: bool) !void {
        try self.writeTag(field_number, .varint);
        try self.writeVarint(if (value) 1 else 0);
    }

    /// Write fixed64
    pub fn writeFixed64(self: *ProtobufEncoder, field_number: u32, value: u64) !void {
        try self.writeTag(field_number, .fixed64);
        try self.buffer.appendSlice(std.mem.asBytes(&value));
    }

    /// Write a nested message field
    pub fn writeMessage(self: *ProtobufEncoder, field_number: u32, data: []const u8) !void {
        try self.writeBytes(field_number, data);
    }
};

/// Perfetto field numbers (simplified subset)
const PerfettoFields = struct {
    // TracePacket fields
    const packet_timestamp = 8;
    const packet_timestamp_clock_id = 58;
    const packet_track_event = 11;
    const packet_track_descriptor = 60;
    const packet_clock_snapshot = 6;
    const packet_trusted_packet_sequence_id = 10;

    // TrackDescriptor fields
    const track_uuid = 1;
    const track_name = 2;
    const track_process = 3;
    const track_thread = 4;

    // ProcessDescriptor fields
    const process_pid = 1;
    const process_name = 6;

    // ThreadDescriptor fields
    const thread_pid = 1;
    const thread_tid = 2;
    const thread_name = 5;

    // TrackEvent fields
    const event_track_uuid = 11;
    const event_timestamp_delta_us = 1;
    const event_type = 9;
    const event_name = 23;
    const event_debug_annotations = 4;

    // DebugAnnotation fields
    const annotation_name = 1;
    const annotation_string_value = 6;
    const annotation_int_value = 2;
};

/// Serialize an event to Perfetto format
pub fn serializeEvent(allocator: std.mem.Allocator, event: events.Event, start_time: i64) ![]u8 {
    var encoder = ProtobufEncoder.init(allocator);
    defer encoder.deinit();

    // Create track event
    var track_event = ProtobufEncoder.init(allocator);
    defer track_event.deinit();

    const current_time = std.time.milliTimestamp();
    const timestamp_delta = current_time - start_time;

    // Write timestamp delta
    try track_event.writeInt64(PerfettoFields.event_timestamp_delta_us, timestamp_delta * 1000);

    // Write event type and data based on event type
    switch (event) {
        .spawn => |spawn| {
            try track_event.writeBytes(PerfettoFields.event_name, "spawn");
            try writeAnnotation(&track_event, allocator, "parent_pid", .{ .int = spawn.parent_pid });
            try writeAnnotation(&track_event, allocator, "child_pid", .{ .int = spawn.child_pid });
        },
        .exec => |exec| {
            try track_event.writeBytes(PerfettoFields.event_name, "exec");
            try writeAnnotation(&track_event, allocator, "executable", .{ .string = exec.executable });
        },
        .exit => |exit| {
            try track_event.writeBytes(PerfettoFields.event_name, "exit");
            try writeAnnotation(&track_event, allocator, "pid", .{ .int = exit.pid });
            try writeAnnotation(&track_event, allocator, "exit_code", .{ .int = exit.exit_code });
        },
        .file_open => |file_open| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_open");
            try writeAnnotation(&track_event, allocator, "path", .{ .string = file_open.path });
            try writeAnnotation(&track_event, allocator, "flags", .{ .int = file_open.flags });
        },
        .file_read => |file_read| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_read");
            try writeAnnotation(&track_event, allocator, "fd", .{ .int = @intCast(file_read.fd) });
            try writeAnnotation(&track_event, allocator, "bytes", .{ .int = @intCast(file_read.bytes) });
        },
        .file_write => |file_write| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_write");
            try writeAnnotation(&track_event, allocator, "fd", .{ .int = @intCast(file_write.fd) });
            try writeAnnotation(&track_event, allocator, "bytes", .{ .int = @intCast(file_write.bytes) });
        },
        .file_close => |file_close| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_close");
            try writeAnnotation(&track_event, allocator, "fd", .{ .int = @intCast(file_close.fd) });
        },
        .file_stat => |file_stat| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_stat");
            try writeAnnotation(&track_event, allocator, "path", .{ .string = file_stat.path });
        },
        .file_unlink => |file_unlink| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_unlink");
            try writeAnnotation(&track_event, allocator, "path", .{ .string = file_unlink.path });
        },
        .file_rename => |file_rename| {
            try track_event.writeBytes(PerfettoFields.event_name, "file_rename");
            try writeAnnotation(&track_event, allocator, "old_path", .{ .string = file_rename.old_path });
            try writeAnnotation(&track_event, allocator, "new_path", .{ .string = file_rename.new_path });
        },
        .connect => |connect| {
            try track_event.writeBytes(PerfettoFields.event_name, "connect");
            try writeAnnotation(&track_event, allocator, "domain", .{ .string = connect.domain });
            try writeAnnotation(&track_event, allocator, "port", .{ .int = connect.port });
        },
        .dns_lookup => |dns| {
            try track_event.writeBytes(PerfettoFields.event_name, "dns_lookup");
            try writeAnnotation(&track_event, allocator, "domain", .{ .string = dns.domain });
            try writeAnnotation(&track_event, allocator, "result_ip", .{ .string = dns.result_ip });
        },
        .send => |send| {
            try track_event.writeBytes(PerfettoFields.event_name, "send");
            try writeAnnotation(&track_event, allocator, "fd", .{ .int = @intCast(send.fd) });
            try writeAnnotation(&track_event, allocator, "bytes", .{ .int = @intCast(send.bytes) });
        },
        .recv => |recv| {
            try track_event.writeBytes(PerfettoFields.event_name, "recv");
            try writeAnnotation(&track_event, allocator, "fd", .{ .int = @intCast(recv.fd) });
            try writeAnnotation(&track_event, allocator, "bytes", .{ .int = @intCast(recv.bytes) });
        },
        .stdout => |stdout| {
            try track_event.writeBytes(PerfettoFields.event_name, "stdout");
            try writeAnnotation(&track_event, allocator, "data", .{ .string = stdout.data });
        },
        .stderr => |stderr| {
            try track_event.writeBytes(PerfettoFields.event_name, "stderr");
            try writeAnnotation(&track_event, allocator, "data", .{ .string = stderr.data });
        },
        .pid_mapping => |mapping| {
            try track_event.writeBytes(PerfettoFields.event_name, "pid_mapping");
            try writeAnnotation(&track_event, allocator, "host_pid", .{ .int = @intCast(mapping.host_pid) });
            try writeAnnotation(&track_event, allocator, "uwrx_pid", .{ .int = mapping.uwrx_pid });
        },
        .clock_sync => |sync| {
            try track_event.writeBytes(PerfettoFields.event_name, "clock_sync");
            try writeAnnotation(&track_event, allocator, "monotonic_ns", .{ .int = @intCast(sync.monotonic_ns) });
        },
    }

    // Wrap in TracePacket
    const track_event_data = try track_event.toOwnedSlice();
    defer allocator.free(track_event_data);

    try encoder.writeMessage(PerfettoFields.packet_track_event, track_event_data);
    try encoder.writeUint32(PerfettoFields.packet_trusted_packet_sequence_id, 1);

    return encoder.toOwnedSlice();
}

const AnnotationValue = union(enum) {
    string: []const u8,
    int: u64,
};

fn writeAnnotation(encoder: *ProtobufEncoder, allocator: std.mem.Allocator, name: []const u8, value: AnnotationValue) !void {
    var annotation = ProtobufEncoder.init(allocator);
    defer annotation.deinit();

    try annotation.writeBytes(PerfettoFields.annotation_name, name);
    switch (value) {
        .string => |s| try annotation.writeBytes(PerfettoFields.annotation_string_value, s),
        .int => |i| try annotation.writeUint64(PerfettoFields.annotation_int_value, i),
    }

    const data = try annotation.toOwnedSlice();
    defer allocator.free(data);
    try encoder.writeMessage(PerfettoFields.event_debug_annotations, data);
}

/// Create a process descriptor track
pub fn createProcessDescriptor(allocator: std.mem.Allocator, pid: u32, name: []const u8) ![]u8 {
    var encoder = ProtobufEncoder.init(allocator);
    defer encoder.deinit();

    var track_desc = ProtobufEncoder.init(allocator);
    defer track_desc.deinit();

    // Track UUID (use pid as uuid for simplicity)
    try track_desc.writeUint64(PerfettoFields.track_uuid, pid);
    try track_desc.writeBytes(PerfettoFields.track_name, name);

    // Process descriptor
    var process_desc = ProtobufEncoder.init(allocator);
    defer process_desc.deinit();
    try process_desc.writeUint32(PerfettoFields.process_pid, pid);
    try process_desc.writeBytes(PerfettoFields.process_name, name);

    const process_data = try process_desc.toOwnedSlice();
    defer allocator.free(process_data);
    try track_desc.writeMessage(PerfettoFields.track_process, process_data);

    const track_data = try track_desc.toOwnedSlice();
    defer allocator.free(track_data);

    try encoder.writeMessage(PerfettoFields.packet_track_descriptor, track_data);

    return encoder.toOwnedSlice();
}

test "protobuf encoding" {
    const allocator = std.testing.allocator;

    var encoder = ProtobufEncoder.init(allocator);
    defer encoder.deinit();

    try encoder.writeVarint(150);
    const data = encoder.buffer.items;
    try std.testing.expectEqual(@as(usize, 2), data.len);
    try std.testing.expectEqual(@as(u8, 0x96), data[0]);
    try std.testing.expectEqual(@as(u8, 0x01), data[1]);
}

test "event serialization" {
    const allocator = std.testing.allocator;

    const event = events.Event{
        .exit = .{
            .pid = 2,
            .exit_code = 0,
        },
    };

    const serialized = try serializeEvent(allocator, event, 0);
    defer allocator.free(serialized);

    try std.testing.expect(serialized.len > 0);
}
