//! Source type definitions and parsing

const std = @import("std");
const host = @import("host.zig");

/// Source types
pub const SourceType = enum {
    host_dir,
    tar,
    git,
    oci,
    squashfs,
};

/// Parsed source specification
pub const SourceSpec = struct {
    /// Destination mount path
    dst: []const u8,
    /// Priority (higher wins)
    priority: i32,
    /// Source type
    source_type: SourceType,
    /// Source path/spec
    source: []const u8,
    /// Optional subpath within source
    subpath: ?[]const u8,
    /// Optional ref (for git)
    ref: ?[]const u8,
};

/// Source interface
pub const Source = struct {
    source_type: SourceType,
    dst: []const u8,
    priority: i32,
    impl: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        exists: *const fn (*anyopaque, []const u8) bool,
        read: *const fn (*anyopaque, []const u8) ?[]const u8,
        list: *const fn (*anyopaque, []const u8, std.mem.Allocator) ?[][]const u8,
        stat: *const fn (*anyopaque, []const u8) ?StatInfo,
        deinit: *const fn (*anyopaque) void,
    };

    pub fn exists(self: *Source, path: []const u8) bool {
        return self.vtable.exists(self.impl, path);
    }

    pub fn read(self: *Source, path: []const u8) ?[]const u8 {
        return self.vtable.read(self.impl, path);
    }

    pub fn list(self: *Source, path: []const u8, allocator: std.mem.Allocator) ?[][]const u8 {
        return self.vtable.list(self.impl, path, allocator);
    }

    pub fn stat(self: *Source, path: []const u8) ?StatInfo {
        return self.vtable.stat(self.impl, path);
    }

    pub fn deinit(self: *Source) void {
        self.vtable.deinit(self.impl);
    }
};

/// File stat info
pub const StatInfo = struct {
    mode: u32,
    size: u64,
    is_dir: bool,
    is_symlink: bool,
};

/// Parse a source specification string
/// Format: <source> where source can be:
///   /path/to/dir                    - host directory
///   tar:/path/to/file.tar[:/subpath] - tarball
///   git:/path/to/repo[:treeish]     - git repository
///   oci:image:tag[:/subpath]        - OCI image
///   squashfs:/path/to/file[:/subpath] - squashfs image
pub fn parseSourceSpec(spec: []const u8) !SourceSpec {
    // Check for type prefix
    if (std.mem.startsWith(u8, spec, "tar:")) {
        return parseTarSpec(spec[4..]);
    } else if (std.mem.startsWith(u8, spec, "git:")) {
        return parseGitSpec(spec[4..]);
    } else if (std.mem.startsWith(u8, spec, "oci:")) {
        return parseOciSpec(spec[4..]);
    } else if (std.mem.startsWith(u8, spec, "squashfs:")) {
        return parseSquashfsSpec(spec[9..]);
    } else {
        // Default: host directory
        return .{
            .dst = "",
            .priority = 0,
            .source_type = .host_dir,
            .source = spec,
            .subpath = null,
            .ref = null,
        };
    }
}

fn parseTarSpec(spec: []const u8) !SourceSpec {
    // Format: /path/to/file.tar[:/subpath]
    if (std.mem.indexOf(u8, spec, ":/")) |idx| {
        return .{
            .dst = "",
            .priority = 0,
            .source_type = .tar,
            .source = spec[0..idx],
            .subpath = spec[idx + 2 ..],
            .ref = null,
        };
    }
    return .{
        .dst = "",
        .priority = 0,
        .source_type = .tar,
        .source = spec,
        .subpath = null,
        .ref = null,
    };
}

fn parseGitSpec(spec: []const u8) !SourceSpec {
    // Format: /path/to/repo[:treeish[:subpath]]
    var parts: [3][]const u8 = undefined;
    var count: usize = 0;

    var iter = std.mem.splitScalar(u8, spec, ':');
    while (iter.next()) |part| {
        if (count < 3) {
            parts[count] = part;
            count += 1;
        }
    }

    return .{
        .dst = "",
        .priority = 0,
        .source_type = .git,
        .source = if (count > 0) parts[0] else spec,
        .ref = if (count > 1) parts[1] else null,
        .subpath = if (count > 2) parts[2] else null,
    };
}

fn parseOciSpec(spec: []const u8) !SourceSpec {
    // Format: image:tag[:/subpath]
    if (std.mem.indexOf(u8, spec, ":/")) |idx| {
        return .{
            .dst = "",
            .priority = 0,
            .source_type = .oci,
            .source = spec[0..idx],
            .subpath = spec[idx + 2 ..],
            .ref = null,
        };
    }
    return .{
        .dst = "",
        .priority = 0,
        .source_type = .oci,
        .source = spec,
        .subpath = null,
        .ref = null,
    };
}

fn parseSquashfsSpec(spec: []const u8) !SourceSpec {
    // Format: /path/to/file[:/subpath]
    if (std.mem.indexOf(u8, spec, ":/")) |idx| {
        return .{
            .dst = "",
            .priority = 0,
            .source_type = .squashfs,
            .source = spec[0..idx],
            .subpath = spec[idx + 2 ..],
            .ref = null,
        };
    }
    return .{
        .dst = "",
        .priority = 0,
        .source_type = .squashfs,
        .source = spec,
        .subpath = null,
        .ref = null,
    };
}

/// Create a source from a specification
pub fn createSource(allocator: std.mem.Allocator, spec: SourceSpec) !Source {
    switch (spec.source_type) {
        .host_dir => {
            const impl = try host.HostSource.create(allocator, spec.source);
            return .{
                .source_type = .host_dir,
                .dst = spec.dst,
                .priority = spec.priority,
                .impl = impl,
                .vtable = &host.HostSource.vtable,
            };
        },
        .tar => {
            // TODO: Implement tar source
            return error.NotImplemented;
        },
        .git => {
            // TODO: Implement git source
            return error.NotImplemented;
        },
        .oci => {
            // TODO: Implement OCI source
            return error.NotImplemented;
        },
        .squashfs => {
            // TODO: Implement squashfs source
            return error.NotImplemented;
        },
    }
}

test "parseSourceSpec host" {
    const spec = try parseSourceSpec("/home/user/project");
    try std.testing.expectEqual(SourceType.host_dir, spec.source_type);
    try std.testing.expectEqualStrings("/home/user/project", spec.source);
}

test "parseSourceSpec tar" {
    const spec = try parseSourceSpec("tar:/path/to/file.tar:/subdir");
    try std.testing.expectEqual(SourceType.tar, spec.source_type);
    try std.testing.expectEqualStrings("/path/to/file.tar", spec.source);
    try std.testing.expectEqualStrings("/subdir", spec.subpath.?);
}

test "parseSourceSpec git" {
    const spec = try parseSourceSpec("git:/path/to/repo:main:src");
    try std.testing.expectEqual(SourceType.git, spec.source_type);
    try std.testing.expectEqualStrings("/path/to/repo", spec.source);
    try std.testing.expectEqualStrings("main", spec.ref.?);
    try std.testing.expectEqualStrings("src", spec.subpath.?);
}
