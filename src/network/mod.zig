//! Network module
//!
//! Implements network isolation with MITM proxying, DNS interception,
//! and loopback IP allocation for domain tracking.

const std = @import("std");

pub const dns = @import("dns.zig");
pub const proxy = @import("proxy.zig");
pub const tls = @import("tls.zig");
pub const loopback = @import("loopback.zig");
pub const git_proto = @import("git.zig");

/// Network state for a supervised run
pub const NetworkState = struct {
    allocator: std.mem.Allocator,
    loopback_state: loopback.LoopbackState,
    dns_state: dns.DnsState,
    proxy_state: proxy.ProxyState,
    tls_state: tls.TlsState,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator, enabled: bool) !NetworkState {
        var loopback_state = loopback.LoopbackState.init(allocator);
        errdefer loopback_state.deinit();

        var dns_state = try dns.DnsState.init(allocator, &loopback_state);
        errdefer dns_state.deinit();

        var tls_state = try tls.TlsState.init(allocator);
        errdefer tls_state.deinit();

        var proxy_state = try proxy.ProxyState.init(allocator, &loopback_state, &tls_state);

        return .{
            .allocator = allocator,
            .loopback_state = loopback_state,
            .dns_state = dns_state,
            .proxy_state = proxy_state,
            .tls_state = tls_state,
            .enabled = enabled,
        };
    }

    pub fn deinit(self: *NetworkState) void {
        self.proxy_state.deinit();
        self.tls_state.deinit();
        self.dns_state.deinit();
        self.loopback_state.deinit();
    }

    /// Get CA certificate
    pub fn getCaCert(self: *NetworkState) []const u8 {
        return self.tls_state.getCaCert();
    }

    /// Resolve domain to loopback IP
    pub fn resolveToLoopback(self: *NetworkState, domain: []const u8) ![]const u8 {
        return self.loopback_state.getOrAllocate(domain);
    }

    /// Get domain for loopback IP
    pub fn getDomainForLoopback(self: *NetworkState, ip: []const u8) ?[]const u8 {
        return self.loopback_state.reverseLookup(ip);
    }
};

test {
    _ = dns;
    _ = proxy;
    _ = tls;
    _ = loopback;
    _ = git_proto;
}
