//! DNS server and interception
//!
//! Intercepts DNS queries and returns allocated loopback IPs
//! instead of real IP addresses.

const std = @import("std");
const loopback = @import("loopback.zig");

/// DNS query types
pub const QueryType = enum(u16) {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    _,
};

/// DNS response codes
pub const ResponseCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3, // NXDOMAIN
    not_implemented = 4,
    refused = 5,
    _,
};

/// DNS state
pub const DnsState = struct {
    allocator: std.mem.Allocator,
    loopback_state: *loopback.LoopbackState,
    /// Socket for DNS server
    socket: ?std.posix.socket_t,
    /// Recorded queries
    queries: std.ArrayList(DnsQuery),

    pub fn init(allocator: std.mem.Allocator, lb_state: *loopback.LoopbackState) !DnsState {
        return .{
            .allocator = allocator,
            .loopback_state = lb_state,
            .socket = null,
            .queries = std.ArrayList(DnsQuery).init(allocator),
        };
    }

    pub fn deinit(self: *DnsState) void {
        if (self.socket) |sock| {
            std.posix.close(sock);
        }
        self.queries.deinit();
    }

    /// Start DNS server on 127.0.0.1:53
    pub fn startServer(self: *DnsState) !void {
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 53);
        try std.posix.bind(sock, &addr.any, addr.getOsSockLen());

        self.socket = sock;
    }

    /// Handle a DNS query
    pub fn handleQuery(self: *DnsState, domain: []const u8, query_type: QueryType) !DnsResponse {
        // Record query
        try self.queries.append(.{
            .domain = try self.allocator.dupe(u8, domain),
            .query_type = query_type,
        });

        // Get loopback IP
        switch (query_type) {
            .A => {
                const ip = try self.loopback_state.getOrAllocate(domain);
                return .{
                    .code = .no_error,
                    .answers = &.{.{ .a = ip }},
                };
            },
            .AAAA => {
                const ip = try self.loopback_state.getOrAllocateV6(domain);
                return .{
                    .code = .no_error,
                    .answers = &.{.{ .aaaa = ip }},
                };
            },
            else => {
                return .{
                    .code = .not_implemented,
                    .answers = &.{},
                };
            },
        }
    }

    /// Generate fake resolv.conf content
    pub fn getResolvConf(_: *DnsState) []const u8 {
        return "nameserver 127.0.0.1\n";
    }
};

/// Recorded DNS query
pub const DnsQuery = struct {
    domain: []const u8,
    query_type: QueryType,
};

/// DNS response
pub const DnsResponse = struct {
    code: ResponseCode,
    answers: []const Answer,

    pub const Answer = union(enum) {
        a: []const u8, // IPv4 address string
        aaaa: []const u8, // IPv6 address string
        cname: []const u8,
    };
};

/// Parse a DNS query packet
pub fn parseQuery(data: []const u8) !struct { domain: []const u8, query_type: QueryType } {
    if (data.len < 12) return error.TooShort;

    // Skip header (12 bytes)
    var offset: usize = 12;

    // Parse question section
    var domain_parts = std.ArrayList([]const u8).init(std.heap.page_allocator);
    defer domain_parts.deinit();

    while (offset < data.len and data[offset] != 0) {
        const label_len = data[offset];
        offset += 1;

        if (offset + label_len > data.len) return error.InvalidLabel;

        try domain_parts.append(data[offset .. offset + label_len]);
        offset += label_len;
    }

    offset += 1; // Skip null terminator

    if (offset + 4 > data.len) return error.TooShort;

    const qtype = std.mem.readInt(u16, data[offset..][0..2], .big);

    // Join domain parts
    var domain = std.ArrayList(u8).init(std.heap.page_allocator);
    for (domain_parts.items, 0..) |part, i| {
        if (i > 0) try domain.append('.');
        try domain.appendSlice(part);
    }

    return .{
        .domain = try domain.toOwnedSlice(),
        .query_type = @enumFromInt(qtype),
    };
}

/// Build a DNS response packet
pub fn buildResponse(allocator: std.mem.Allocator, query: []const u8, response: DnsResponse) ![]u8 {
    _ = allocator;
    _ = response;

    // Simple response building - would need full DNS packet construction
    var result = std.ArrayList(u8).init(std.heap.page_allocator);

    // Copy query ID
    try result.appendSlice(query[0..2]);

    // Flags: response, recursion available
    try result.appendSlice(&[_]u8{ 0x81, 0x80 });

    // Questions: 1, Answers: 1, Authority: 0, Additional: 0
    try result.appendSlice(&[_]u8{ 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });

    // Copy question section
    var offset: usize = 12;
    while (offset < query.len and query[offset] != 0) {
        offset += 1 + query[offset];
    }
    offset += 5; // null + qtype + qclass

    try result.appendSlice(query[12..offset]);

    // Answer section (simplified)
    // Name pointer to question
    try result.appendSlice(&[_]u8{ 0xc0, 0x0c });
    // Type A
    try result.appendSlice(&[_]u8{ 0x00, 0x01 });
    // Class IN
    try result.appendSlice(&[_]u8{ 0x00, 0x01 });
    // TTL: 300
    try result.appendSlice(&[_]u8{ 0x00, 0x00, 0x01, 0x2c });
    // Data length: 4
    try result.appendSlice(&[_]u8{ 0x00, 0x04 });
    // IP: 127.0.0.2 (placeholder)
    try result.appendSlice(&[_]u8{ 127, 0, 0, 2 });

    return result.toOwnedSlice();
}

test "DNS query parsing" {
    // Simple test DNS query for "example.com"
    const query = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // Questions
        0x00, 0x00, // Answers
        0x00, 0x00, // Authority
        0x00, 0x00, // Additional
        // Question
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00, // End
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
    };

    const result = try parseQuery(&query);
    defer std.heap.page_allocator.free(result.domain);

    try std.testing.expectEqualStrings("example.com", result.domain);
    try std.testing.expectEqual(QueryType.A, result.query_type);
}
