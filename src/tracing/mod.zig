//! Tracing module
//!
//! Handles trace event recording, Perfetto format output,
//! buffer management, and trace storage.

const std = @import("std");

pub const perfetto = @import("perfetto.zig");
pub const buffer = @import("buffer.zig");
pub const events = @import("events.zig");
pub const merger = @import("merger.zig");
pub const storage = @import("storage.zig");

/// Tracer instance for a single process
pub const Tracer = struct {
    allocator: std.mem.Allocator,
    trace_buffer: buffer.TraceBuffer,
    uwrx_pid: u32,
    start_time: i64,

    pub fn init(allocator: std.mem.Allocator, traces_dir: []const u8, uwrx_pid: u32) !Tracer {
        const trace_buffer = try buffer.TraceBuffer.init(allocator, traces_dir, uwrx_pid);

        return .{
            .allocator = allocator,
            .trace_buffer = trace_buffer,
            .uwrx_pid = uwrx_pid,
            .start_time = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *Tracer) void {
        self.trace_buffer.deinit();
    }

    /// Record a trace event
    pub fn record(self: *Tracer, event: events.Event) !void {
        const serialized = try perfetto.serializeEvent(self.allocator, event, self.start_time);
        defer self.allocator.free(serialized);

        try self.trace_buffer.write(serialized);
    }

    /// Record process spawn event
    pub fn recordSpawn(self: *Tracer, child_uwrx_pid: u32, command: []const []const u8) !void {
        try self.record(.{
            .spawn = .{
                .parent_pid = self.uwrx_pid,
                .child_pid = child_uwrx_pid,
                .command = command,
            },
        });
    }

    /// Record file open event
    pub fn recordOpen(self: *Tracer, path: []const u8, flags: u32, result_fd: i32) !void {
        try self.record(.{
            .file_open = .{
                .pid = self.uwrx_pid,
                .path = path,
                .flags = flags,
                .result_fd = result_fd,
            },
        });
    }

    /// Record file read event
    pub fn recordRead(self: *Tracer, fd: i32, bytes_read: usize) !void {
        try self.record(.{
            .file_read = .{
                .pid = self.uwrx_pid,
                .fd = fd,
                .bytes = bytes_read,
            },
        });
    }

    /// Record file write event
    pub fn recordWrite(self: *Tracer, fd: i32, bytes_written: usize) !void {
        try self.record(.{
            .file_write = .{
                .pid = self.uwrx_pid,
                .fd = fd,
                .bytes = bytes_written,
            },
        });
    }

    /// Record stdout output
    pub fn recordStdout(self: *Tracer, data: []const u8) !void {
        try self.record(.{
            .stdout = .{
                .pid = self.uwrx_pid,
                .data = data,
            },
        });
    }

    /// Record stderr output
    pub fn recordStderr(self: *Tracer, data: []const u8) !void {
        try self.record(.{
            .stderr = .{
                .pid = self.uwrx_pid,
                .data = data,
            },
        });
    }

    /// Record process exit
    pub fn recordExit(self: *Tracer, exit_code: u32) !void {
        try self.record(.{
            .exit = .{
                .pid = self.uwrx_pid,
                .exit_code = exit_code,
            },
        });
    }

    /// Record network connection
    pub fn recordConnect(self: *Tracer, domain: []const u8, port: u16) !void {
        try self.record(.{
            .connect = .{
                .pid = self.uwrx_pid,
                .domain = domain,
                .port = port,
            },
        });
    }

    /// Record DNS lookup
    pub fn recordDnsLookup(self: *Tracer, domain: []const u8, result_ip: []const u8) !void {
        try self.record(.{
            .dns_lookup = .{
                .pid = self.uwrx_pid,
                .domain = domain,
                .result_ip = result_ip,
            },
        });
    }

    /// Flush buffered events
    pub fn flush(self: *Tracer) !void {
        try self.trace_buffer.flush();
    }
};

test {
    _ = perfetto;
    _ = buffer;
    _ = events;
    _ = merger;
    _ = storage;
}
