//! HTTP/HTTPS MITM proxy
//!
//! Intercepts HTTP and HTTPS traffic, records requests and responses,
//! and can replay from cache.

const std = @import("std");
const loopback = @import("loopback.zig");
const tls_mod = @import("tls.zig");

/// Proxy state
pub const ProxyState = struct {
    allocator: std.mem.Allocator,
    loopback_state: *loopback.LoopbackState,
    tls_state: *tls_mod.TlsState,
    /// Active connections
    connections: std.ArrayList(Connection),
    /// Recorded traffic
    traffic: std.ArrayList(TrafficRecord),

    pub fn init(
        allocator: std.mem.Allocator,
        lb_state: *loopback.LoopbackState,
        tls_state: *tls_mod.TlsState,
    ) !ProxyState {
        return .{
            .allocator = allocator,
            .loopback_state = lb_state,
            .tls_state = tls_state,
            .connections = std.ArrayList(Connection).init(allocator),
            .traffic = std.ArrayList(TrafficRecord).init(allocator),
        };
    }

    pub fn deinit(self: *ProxyState) void {
        for (self.connections.items) |*conn| {
            conn.deinit();
        }
        self.connections.deinit();

        for (self.traffic.items) |*record| {
            record.deinit(self.allocator);
        }
        self.traffic.deinit();
    }

    /// Handle incoming connection
    pub fn handleConnection(self: *ProxyState, client_fd: std.posix.socket_t, client_addr: std.net.Address) !void {
        // Determine target domain from loopback IP
        var ip_buf: [64]u8 = undefined;
        const ip_str = client_addr.format(&ip_buf, .{}) catch return;

        const domain = self.loopback_state.reverseLookup(ip_str) orelse return error.UnknownDomain;

        // Create connection handler
        const conn = Connection{
            .allocator = self.allocator,
            .client_fd = client_fd,
            .domain = domain,
            .is_tls = false,
            .tls_state = self.tls_state,
        };

        try self.connections.append(conn);
    }

    /// Record traffic
    pub fn recordTraffic(self: *ProxyState, record: TrafficRecord) !void {
        try self.traffic.append(record);
    }
};

/// Connection handler
pub const Connection = struct {
    allocator: std.mem.Allocator,
    client_fd: std.posix.socket_t,
    upstream_fd: ?std.posix.socket_t = null,
    domain: []const u8,
    is_tls: bool,
    tls_state: *tls_mod.TlsState,

    pub fn deinit(self: *Connection) void {
        if (self.upstream_fd) |fd| {
            std.posix.close(fd);
        }
        std.posix.close(self.client_fd);
    }

    /// Process the connection
    pub fn process(self: *Connection) !void {
        // Read initial data to detect TLS
        var buf: [1024]u8 = undefined;
        const n = std.posix.read(self.client_fd, &buf) catch return;
        if (n == 0) return;

        // Check for TLS ClientHello
        self.is_tls = buf[0] == 0x16 and buf[1] == 0x03;

        if (self.is_tls) {
            try self.handleTls(buf[0..n]);
        } else {
            try self.handleHttp(buf[0..n]);
        }
    }

    fn handleTls(self: *Connection, initial_data: []const u8) !void {
        _ = initial_data;

        // Get certificate for domain
        const cert = try self.tls_state.getCertForDomain(self.domain);
        _ = cert;

        // TODO: Implement TLS handshake and proxying
    }

    fn handleHttp(_: *Connection, initial_data: []const u8) !void {
        // Parse HTTP request
        const request = try HttpRequest.parse(initial_data);
        _ = request;

        // TODO: Forward to upstream, record, return response
    }
};

/// Traffic record
pub const TrafficRecord = struct {
    domain: []const u8,
    path: []const u8,
    method: []const u8,
    request_headers: []const u8,
    request_body: ?[]const u8,
    response_status: u16,
    response_headers: []const u8,
    response_body: ?[]const u8,
    timestamp: i64,

    pub fn deinit(self: *TrafficRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.path);
        allocator.free(self.method);
        allocator.free(self.request_headers);
        if (self.request_body) |b| allocator.free(b);
        allocator.free(self.response_headers);
        if (self.response_body) |b| allocator.free(b);
    }
};

/// HTTP request parser
pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    version: []const u8,
    headers: std.StringHashMap([]const u8),

    pub fn parse(data: []const u8) !HttpRequest {
        var lines = std.mem.splitSequence(u8, data, "\r\n");

        // Request line
        const request_line = lines.next() orelse return error.EmptyRequest;
        var parts = std.mem.splitScalar(u8, request_line, ' ');

        const method = parts.next() orelse return error.InvalidRequest;
        const path = parts.next() orelse return error.InvalidRequest;
        const version = parts.next() orelse return error.InvalidRequest;

        // Headers
        var headers = std.StringHashMap([]const u8).init(std.heap.page_allocator);
        while (lines.next()) |line| {
            if (line.len == 0) break;

            if (std.mem.indexOf(u8, line, ": ")) |colon| {
                const name = line[0..colon];
                const value = line[colon + 2 ..];
                try headers.put(name, value);
            }
        }

        return .{
            .method = method,
            .path = path,
            .version = version,
            .headers = headers,
        };
    }
};

test "HTTP request parsing" {
    const request = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var parsed = try HttpRequest.parse(request);
    defer parsed.headers.deinit();

    try std.testing.expectEqualStrings("GET", parsed.method);
    try std.testing.expectEqualStrings("/path", parsed.path);
}
