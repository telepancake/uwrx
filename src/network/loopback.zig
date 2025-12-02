//! Loopback IP allocation per domain
//!
//! Allocates unique loopback IPs (from 127.0.0.0/8) for each domain
//! to track which connections go to which domains.

const std = @import("std");

/// Loopback state manager
pub const LoopbackState = struct {
    allocator: std.mem.Allocator,
    /// Domain -> IPv4 mapping
    ipv4_map: std.StringHashMap([]u8),
    /// Domain -> IPv6 mapping
    ipv6_map: std.StringHashMap([]u8),
    /// Reverse lookup: IP -> domain
    reverse_map: std.StringHashMap([]const u8),
    /// PRNG for random IP generation
    prng: std.Random.DefaultPrng,
    /// Next sequential allocation (fallback)
    next_ipv4: u32,

    pub fn init(allocator: std.mem.Allocator) LoopbackState {
        return .{
            .allocator = allocator,
            .ipv4_map = std.StringHashMap([]u8).init(allocator),
            .ipv6_map = std.StringHashMap([]u8).init(allocator),
            .reverse_map = std.StringHashMap([]const u8).init(allocator),
            .prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp())),
            .next_ipv4 = 0x7f000100, // Start at 127.0.1.0
        };
    }

    pub fn deinit(self: *LoopbackState) void {
        var it = self.ipv4_map.valueIterator();
        while (it.next()) |ip| {
            self.allocator.free(ip.*);
        }
        self.ipv4_map.deinit();

        var it6 = self.ipv6_map.valueIterator();
        while (it6.next()) |ip| {
            self.allocator.free(ip.*);
        }
        self.ipv6_map.deinit();

        self.reverse_map.deinit();
    }

    /// Get or allocate IPv4 loopback for domain
    pub fn getOrAllocate(self: *LoopbackState, domain: []const u8) ![]const u8 {
        if (self.ipv4_map.get(domain)) |ip| {
            return ip;
        }

        // Allocate new IP
        const ip = try self.allocateIPv4();
        const domain_copy = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(domain_copy);

        try self.ipv4_map.put(domain_copy, ip);
        try self.reverse_map.put(ip, domain_copy);

        return ip;
    }

    /// Get or allocate IPv6 loopback for domain
    pub fn getOrAllocateV6(self: *LoopbackState, domain: []const u8) ![]const u8 {
        if (self.ipv6_map.get(domain)) |ip| {
            return ip;
        }

        // Allocate new IPv6
        const ip = try self.allocateIPv6();
        const domain_copy = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(domain_copy);

        try self.ipv6_map.put(domain_copy, ip);
        try self.reverse_map.put(ip, domain_copy);

        return ip;
    }

    /// Allocate a new IPv4 loopback address
    fn allocateIPv4(self: *LoopbackState) ![]u8 {
        // Try random allocation first
        var attempts: u32 = 0;
        while (attempts < 100) : (attempts += 1) {
            const random = self.prng.random();

            // Generate random in 127.x.y.z range
            // Avoid 127.0.0.0/24 and 127.255.255.0/24
            const byte1: u8 = @truncate(random.int(u8) | 1); // Ensure not 0
            const byte2 = random.int(u8);
            const byte3: u8 = @truncate(random.int(u8) & 0xFE); // Avoid .255

            var ip_str = try self.allocator.alloc(u8, 15);
            const len = std.fmt.bufPrint(ip_str, "127.{d}.{d}.{d}", .{ byte1, byte2, byte3 }) catch unreachable;
            ip_str = self.allocator.realloc(ip_str, len.len) catch ip_str;

            // Check if already used
            if (!self.reverse_map.contains(ip_str)) {
                return ip_str;
            }
            self.allocator.free(ip_str);
        }

        // Fallback to sequential
        while (self.next_ipv4 < 0x7ffffffe) {
            const b0: u8 = @truncate((self.next_ipv4 >> 24) & 0xFF);
            const b1: u8 = @truncate((self.next_ipv4 >> 16) & 0xFF);
            const b2: u8 = @truncate((self.next_ipv4 >> 8) & 0xFF);
            const b3: u8 = @truncate(self.next_ipv4 & 0xFF);
            self.next_ipv4 += 1;

            var ip_str = try self.allocator.alloc(u8, 15);
            const len = std.fmt.bufPrint(ip_str, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 }) catch unreachable;
            ip_str = self.allocator.realloc(ip_str, len.len) catch ip_str;

            if (!self.reverse_map.contains(ip_str)) {
                return ip_str;
            }
            self.allocator.free(ip_str);
        }

        return error.NoAvailableIP;
    }

    /// Allocate a new IPv6 loopback address
    fn allocateIPv6(self: *LoopbackState) ![]u8 {
        // Use ::1:xxxx:xxxx format
        const random = self.prng.random();
        const word1 = random.int(u16);
        const word2 = random.int(u16);

        const ip_str = try self.allocator.alloc(u8, 32);
        const len = std.fmt.bufPrint(ip_str, "::1:{x:0>4}:{x:0>4}", .{ word1, word2 }) catch unreachable;
        return self.allocator.realloc(ip_str, len.len) catch ip_str;
    }

    /// Reverse lookup: IP -> domain
    pub fn reverseLookup(self: *LoopbackState, ip: []const u8) ?[]const u8 {
        return self.reverse_map.get(ip);
    }

    /// Set a specific mapping (for replay)
    pub fn setMapping(self: *LoopbackState, domain: []const u8, ipv4: ?[]const u8, ipv6: ?[]const u8) !void {
        const domain_copy = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(domain_copy);

        if (ipv4) |ip| {
            const ip_copy = try self.allocator.dupe(u8, ip);
            try self.ipv4_map.put(domain_copy, ip_copy);
            try self.reverse_map.put(ip_copy, domain_copy);
        }

        if (ipv6) |ip| {
            const ip_copy = try self.allocator.dupe(u8, ip);
            try self.ipv6_map.put(domain_copy, ip_copy);
            try self.reverse_map.put(ip_copy, domain_copy);
        }
    }
};

test "LoopbackState allocation" {
    const allocator = std.testing.allocator;

    var state = LoopbackState.init(allocator);
    defer state.deinit();

    const ip1 = try state.getOrAllocate("example.com");
    const ip2 = try state.getOrAllocate("example.org");

    // Different domains should get different IPs
    try std.testing.expect(!std.mem.eql(u8, ip1, ip2));

    // Same domain should get same IP
    const ip1_again = try state.getOrAllocate("example.com");
    try std.testing.expectEqualStrings(ip1, ip1_again);

    // Reverse lookup should work
    const domain = state.reverseLookup(ip1);
    try std.testing.expect(domain != null);
    try std.testing.expectEqualStrings("example.com", domain.?);
}
