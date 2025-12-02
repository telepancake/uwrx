//! Path remapping for special paths
//!
//! Handles remapping of special paths like CA certificates,
//! /dev/urandom, /etc/resolv.conf, etc.

const std = @import("std");

/// Special path mappings
pub const SpecialPath = enum {
    ca_certificates,
    resolv_conf,
    dev_urandom,
    dev_random,
    proc_self,
    none,
};

/// Check if a path needs special handling
pub fn getSpecialPath(path: []const u8) SpecialPath {
    // CA certificate locations
    const ca_paths = [_][]const u8{
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    };

    for (ca_paths) |ca_path| {
        if (std.mem.eql(u8, path, ca_path)) {
            return .ca_certificates;
        }
    }

    if (std.mem.eql(u8, path, "/etc/resolv.conf")) {
        return .resolv_conf;
    }

    if (std.mem.eql(u8, path, "/dev/urandom")) {
        return .dev_urandom;
    }

    if (std.mem.eql(u8, path, "/dev/random")) {
        return .dev_random;
    }

    if (std.mem.startsWith(u8, path, "/proc/self/")) {
        return .proc_self;
    }

    return .none;
}

/// Path remapper state
pub const PathRemapper = struct {
    allocator: std.mem.Allocator,
    /// Path to uwrx's CA certificate
    ca_cert_path: ?[]const u8,
    /// Path to uwrx's resolv.conf
    resolv_conf_path: ?[]const u8,
    /// PRNG file descriptor for /dev/urandom emulation
    prng_fd: ?i32,

    pub fn init(allocator: std.mem.Allocator) PathRemapper {
        return .{
            .allocator = allocator,
            .ca_cert_path = null,
            .resolv_conf_path = null,
            .prng_fd = null,
        };
    }

    pub fn deinit(self: *PathRemapper) void {
        if (self.ca_cert_path) |p| self.allocator.free(p);
        if (self.resolv_conf_path) |p| self.allocator.free(p);
    }

    /// Set the CA certificate path
    pub fn setCaCertPath(self: *PathRemapper, path: []const u8) !void {
        if (self.ca_cert_path) |p| self.allocator.free(p);
        self.ca_cert_path = try self.allocator.dupe(u8, path);
    }

    /// Set the resolv.conf path
    pub fn setResolvConfPath(self: *PathRemapper, path: []const u8) !void {
        if (self.resolv_conf_path) |p| self.allocator.free(p);
        self.resolv_conf_path = try self.allocator.dupe(u8, path);
    }

    /// Remap a path if needed
    pub fn remap(self: *PathRemapper, path: []const u8) ?[]const u8 {
        switch (getSpecialPath(path)) {
            .ca_certificates => return self.ca_cert_path,
            .resolv_conf => return self.resolv_conf_path,
            .dev_urandom, .dev_random => return null, // Handled specially
            .proc_self => return null, // Pass through
            .none => return null,
        }
    }

    /// Check if path is a random device
    pub fn isRandomDevice(path: []const u8) bool {
        const special = getSpecialPath(path);
        return special == .dev_urandom or special == .dev_random;
    }
};

/// Normalize a path (resolve ., .., symlinks conceptually)
pub fn normalizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var components = std.ArrayList([]const u8).init(allocator);
    defer components.deinit();

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) {
            continue;
        } else if (std.mem.eql(u8, component, "..")) {
            _ = components.popOrNull();
        } else {
            try components.append(component);
        }
    }

    // Build result
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    if (path.len > 0 and path[0] == '/') {
        try result.append('/');
    }

    for (components.items, 0..) |component, i| {
        if (i > 0) try result.append('/');
        try result.appendSlice(component);
    }

    if (result.items.len == 0) {
        try result.append('/');
    }

    return result.toOwnedSlice();
}

/// Join paths
pub fn joinPath(allocator: std.mem.Allocator, base: []const u8, rel: []const u8) ![]u8 {
    if (rel.len > 0 and rel[0] == '/') {
        return allocator.dupe(u8, rel);
    }

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    try result.appendSlice(base);
    if (base.len > 0 and base[base.len - 1] != '/') {
        try result.append('/');
    }
    try result.appendSlice(rel);

    return result.toOwnedSlice();
}

test "getSpecialPath" {
    try std.testing.expectEqual(SpecialPath.ca_certificates, getSpecialPath("/etc/ssl/certs/ca-certificates.crt"));
    try std.testing.expectEqual(SpecialPath.resolv_conf, getSpecialPath("/etc/resolv.conf"));
    try std.testing.expectEqual(SpecialPath.dev_urandom, getSpecialPath("/dev/urandom"));
    try std.testing.expectEqual(SpecialPath.none, getSpecialPath("/usr/bin/ls"));
}

test "normalizePath" {
    const allocator = std.testing.allocator;

    const p1 = try normalizePath(allocator, "/foo/bar/../baz");
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("/foo/baz", p1);

    const p2 = try normalizePath(allocator, "/foo/./bar");
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("/foo/bar", p2);
}
