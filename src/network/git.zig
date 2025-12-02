//! Git repository mirroring
//!
//! Detects git protocol traffic and mirrors repositories locally.

const std = @import("std");

/// Git protocol detection
pub const GitProtocol = enum {
    git_native, // git://
    http_smart, // HTTP smart protocol
    http_dumb, // HTTP dumb protocol
    ssh, // SSH (not supported in MITM)
};

/// Git repository state
pub const GitRepoState = struct {
    allocator: std.mem.Allocator,
    /// Local mirror path
    mirror_path: []const u8,
    /// Remote URL
    remote_url: []const u8,
    /// Last fetch time
    last_fetch: i64,

    pub fn init(allocator: std.mem.Allocator, mirror_path: []const u8, remote_url: []const u8) !GitRepoState {
        return .{
            .allocator = allocator,
            .mirror_path = try allocator.dupe(u8, mirror_path),
            .remote_url = try allocator.dupe(u8, remote_url),
            .last_fetch = 0,
        };
    }

    pub fn deinit(self: *GitRepoState) void {
        self.allocator.free(self.mirror_path);
        self.allocator.free(self.remote_url);
    }
};

/// Detect if HTTP request is git protocol
pub fn isGitRequest(path: []const u8, method: []const u8) bool {
    // Smart protocol endpoints
    if (std.mem.endsWith(u8, path, "/info/refs")) return true;
    if (std.mem.endsWith(u8, path, "/git-upload-pack")) return true;
    if (std.mem.endsWith(u8, path, "/git-receive-pack")) return true;

    // Dumb protocol
    if (std.mem.endsWith(u8, path, "/HEAD")) return true;
    if (std.mem.indexOf(u8, path, "/objects/") != null) return true;
    if (std.mem.indexOf(u8, path, "/refs/") != null) return true;

    _ = method;
    return false;
}

/// Extract repository path from URL
pub fn extractRepoPath(path: []const u8) ?[]const u8 {
    // Remove known suffixes
    var repo_path = path;

    const suffixes = [_][]const u8{
        "/info/refs",
        "/git-upload-pack",
        "/git-receive-pack",
        "/HEAD",
        ".git",
    };

    for (suffixes) |suffix| {
        if (std.mem.endsWith(u8, repo_path, suffix)) {
            repo_path = repo_path[0 .. repo_path.len - suffix.len];
            break;
        }
    }

    // Find /objects/ or /refs/ and truncate
    if (std.mem.indexOf(u8, repo_path, "/objects/")) |idx| {
        repo_path = repo_path[0..idx];
    }
    if (std.mem.indexOf(u8, repo_path, "/refs/")) |idx| {
        repo_path = repo_path[0..idx];
    }

    if (repo_path.len == 0) return null;
    return repo_path;
}

/// Git pack protocol helpers
pub const PackProtocol = struct {
    /// Packet line format
    pub fn writePacketLine(writer: anytype, data: []const u8) !void {
        if (data.len == 0) {
            try writer.writeAll("0000");
        } else {
            const len = data.len + 4;
            var len_buf: [4]u8 = undefined;
            _ = std.fmt.bufPrint(&len_buf, "{x:0>4}", .{len}) catch unreachable;
            try writer.writeAll(&len_buf);
            try writer.writeAll(data);
        }
    }

    /// Read packet line
    pub fn readPacketLine(reader: anytype) !?[]const u8 {
        var len_buf: [4]u8 = undefined;
        const len_read = reader.readAll(&len_buf) catch return null;
        if (len_read != 4) return null;

        const len = std.fmt.parseInt(usize, &len_buf, 16) catch return null;
        if (len == 0) return &.{};
        if (len < 4) return error.InvalidPacket;

        const data_len = len - 4;
        var data: [65536]u8 = undefined;
        const data_read = reader.readAll(data[0..data_len]) catch return null;
        if (data_read != data_len) return null;

        return data[0..data_len];
    }
};

test "isGitRequest" {
    try std.testing.expect(isGitRequest("/repo.git/info/refs", "GET"));
    try std.testing.expect(isGitRequest("/repo.git/git-upload-pack", "POST"));
    try std.testing.expect(!isGitRequest("/index.html", "GET"));
}

test "extractRepoPath" {
    const p1 = extractRepoPath("/user/repo.git/info/refs");
    try std.testing.expect(p1 != null);
    try std.testing.expectEqualStrings("/user/repo", p1.?);
}
