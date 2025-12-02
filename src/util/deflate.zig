//! DEFLATE compression utilities for trace files
//! Uses Zig's standard library compression

const std = @import("std");

/// Compress data using DEFLATE algorithm
pub fn compress(allocator_inst: std.mem.Allocator, data: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator_inst);
    errdefer result.deinit();

    var compressor = try std.compress.zlib.compressor(result.writer(), .{});
    try compressor.writer().writeAll(data);
    try compressor.finish();

    return result.toOwnedSlice();
}

/// Decompress DEFLATE-compressed data
pub fn decompress(allocator_inst: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator_inst);
    errdefer result.deinit();

    var fbs = std.io.fixedBufferStream(compressed);
    var decompressor = std.compress.zlib.decompressor(fbs.reader());

    const reader = decompressor.reader();
    while (true) {
        const byte = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        try result.append(byte);
    }

    return result.toOwnedSlice();
}

/// Streaming compressor for large data
pub const StreamCompressor = struct {
    inner: std.compress.zlib.Compressor(std.ArrayList(u8).Writer),
    buffer: std.ArrayList(u8),

    pub fn init(allocator_inst: std.mem.Allocator) !StreamCompressor {
        var buffer = std.ArrayList(u8).init(allocator_inst);
        return .{
            .inner = try std.compress.zlib.compressor(buffer.writer(), .{}),
            .buffer = buffer,
        };
    }

    pub fn write(self: *StreamCompressor, data: []const u8) !void {
        try self.inner.writer().writeAll(data);
    }

    pub fn finish(self: *StreamCompressor) ![]u8 {
        try self.inner.finish();
        return self.buffer.toOwnedSlice();
    }

    pub fn deinit(self: *StreamCompressor) void {
        self.buffer.deinit();
    }
};

test "compress and decompress" {
    const allocator_inst = std.testing.allocator;
    const original = "Hello, World! This is a test of DEFLATE compression.";

    const compressed = try compress(allocator_inst, original);
    defer allocator_inst.free(compressed);

    const decompressed = try decompress(allocator_inst, compressed);
    defer allocator_inst.free(decompressed);

    try std.testing.expectEqualSlices(u8, original, decompressed);
}
