//! IPC between manager threads and supervisor
//!
//! Uses Unix domain sockets for low-latency communication
//! between managed processes and the supervisor.

const std = @import("std");
const linux = @import("../util/linux.zig");

/// IPC message types
pub const MessageType = enum(u8) {
    process_start,
    process_exit,
    open_socket,
    socket_result,
    trace_event,
};

/// IPC message header
pub const MessageHeader = extern struct {
    msg_type: MessageType,
    length: u32,
};

/// Process start message
pub const ProcessStartMsg = struct {
    host_pid: std.os.linux.pid_t,
    uwrx_pid: u32,
};

/// Process exit message
pub const ProcessExitMsg = struct {
    uwrx_pid: u32,
    exit_status: u32,
};

/// Socket request message
pub const OpenSocketMsg = struct {
    domain: i32,
    sock_type: i32,
    protocol: i32,
};

/// Socket result message
pub const SocketResultMsg = struct {
    fd: linux.fd_t,
    @"error": i32,
};

/// IPC message union
pub const Message = union(MessageType) {
    process_start: ProcessStartMsg,
    process_exit: ProcessExitMsg,
    open_socket: OpenSocketMsg,
    socket_result: SocketResultMsg,
    trace_event: []const u8,
};

/// Supervisor connection for manager threads
pub const SupervisorConnection = struct {
    /// Socket for sending messages
    send_fd: linux.fd_t,
    /// Socket for receiving responses
    recv_fd: linux.fd_t,
    /// Parent's end of the send socket (to close in child)
    parent_send_fd: linux.fd_t,
    /// Parent's end of the recv socket (to close in child)
    parent_recv_fd: linux.fd_t,

    /// Create a new supervisor connection (socket pair)
    pub fn create() !SupervisorConnection {
        // Create socket pair for send
        var send_pair: [2]linux.fd_t = undefined;
        if (std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &send_pair) != 0) {
            return error.SocketPairFailed;
        }

        // Create socket pair for recv
        var recv_pair: [2]linux.fd_t = undefined;
        if (std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &recv_pair) != 0) {
            _ = std.os.linux.close(send_pair[0]);
            _ = std.os.linux.close(send_pair[1]);
            return error.SocketPairFailed;
        }

        return .{
            .send_fd = send_pair[0], // Child sends on this
            .recv_fd = recv_pair[1], // Child receives on this
            .parent_send_fd = send_pair[1], // Parent receives on this
            .parent_recv_fd = recv_pair[0], // Parent sends on this
        };
    }

    /// Close parent-side fds (call in child after fork)
    pub fn closeParentEnd(self: *SupervisorConnection) void {
        _ = std.os.linux.close(self.parent_send_fd);
        _ = std.os.linux.close(self.parent_recv_fd);
        self.parent_send_fd = -1;
        self.parent_recv_fd = -1;
    }

    /// Close child-side fds (call in parent after fork)
    pub fn closeChildEnd(self: *SupervisorConnection) void {
        _ = std.os.linux.close(self.send_fd);
        _ = std.os.linux.close(self.recv_fd);
        self.send_fd = -1;
        self.recv_fd = -1;
    }

    pub fn deinit(self: *SupervisorConnection) void {
        if (self.send_fd >= 0) _ = std.os.linux.close(self.send_fd);
        if (self.recv_fd >= 0) _ = std.os.linux.close(self.recv_fd);
        if (self.parent_send_fd >= 0) _ = std.os.linux.close(self.parent_send_fd);
        if (self.parent_recv_fd >= 0) _ = std.os.linux.close(self.parent_recv_fd);
    }

    /// Send a message to the supervisor
    pub fn sendMessage(self: *SupervisorConnection, msg: Message) !void {
        var buffer: [1024]u8 = undefined;
        var offset: usize = @sizeOf(MessageHeader);

        // Serialize message
        switch (msg) {
            .process_start => |ps| {
                const bytes = std.mem.asBytes(&ps);
                @memcpy(buffer[offset .. offset + bytes.len], bytes);
                offset += bytes.len;
            },
            .process_exit => |pe| {
                const bytes = std.mem.asBytes(&pe);
                @memcpy(buffer[offset .. offset + bytes.len], bytes);
                offset += bytes.len;
            },
            .open_socket => |os| {
                const bytes = std.mem.asBytes(&os);
                @memcpy(buffer[offset .. offset + bytes.len], bytes);
                offset += bytes.len;
            },
            .socket_result => |sr| {
                const bytes = std.mem.asBytes(&sr);
                @memcpy(buffer[offset .. offset + bytes.len], bytes);
                offset += bytes.len;
            },
            .trace_event => |te| {
                @memcpy(buffer[offset .. offset + te.len], te);
                offset += te.len;
            },
        }

        // Write header
        const header = MessageHeader{
            .msg_type = msg,
            .length = @intCast(offset - @sizeOf(MessageHeader)),
        };
        const header_bytes = std.mem.asBytes(&header);
        @memcpy(buffer[0..header_bytes.len], header_bytes);

        // Send
        const written = std.os.linux.write(self.send_fd, &buffer, offset);
        if (written != offset) {
            return error.WriteFailed;
        }
    }

    /// Receive a message from the supervisor
    pub fn recvMessage(self: *SupervisorConnection, allocator: std.mem.Allocator) !Message {
        // Read header
        var header: MessageHeader = undefined;
        const header_bytes = std.mem.asBytes(&header);
        const read_result = std.os.linux.read(self.recv_fd, header_bytes.ptr, header_bytes.len);
        if (read_result != header_bytes.len) {
            return error.ReadFailed;
        }

        // Read payload
        const payload = try allocator.alloc(u8, header.length);
        defer allocator.free(payload);

        const payload_read = std.os.linux.read(self.recv_fd, payload.ptr, payload.len);
        if (payload_read != payload.len) {
            return error.ReadFailed;
        }

        // Deserialize
        return switch (header.msg_type) {
            .process_start => .{ .process_start = std.mem.bytesAsValue(ProcessStartMsg, payload[0..@sizeOf(ProcessStartMsg)]).* },
            .process_exit => .{ .process_exit = std.mem.bytesAsValue(ProcessExitMsg, payload[0..@sizeOf(ProcessExitMsg)]).* },
            .open_socket => .{ .open_socket = std.mem.bytesAsValue(OpenSocketMsg, payload[0..@sizeOf(OpenSocketMsg)]).* },
            .socket_result => .{ .socket_result = std.mem.bytesAsValue(SocketResultMsg, payload[0..@sizeOf(SocketResultMsg)]).* },
            .trace_event => .{ .trace_event = try allocator.dupe(u8, payload) },
        };
    }
};

test "message serialization" {
    const msg = Message{ .process_start = .{ .host_pid = 1234, .uwrx_pid = 2 } };
    try std.testing.expectEqual(MessageType.process_start, std.meta.activeTag(msg));
}
