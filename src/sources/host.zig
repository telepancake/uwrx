//! Host directory source implementation
//!
//! Provides read-only access to a directory on the host filesystem.

const std = @import("std");
const types = @import("types.zig");

/// Host directory source
pub const HostSource = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,

    pub const vtable = types.Source.VTable{
        .exists = existsFn,
        .read = readFn,
        .list = listFn,
        .stat = statFn,
        .deinit = deinitFn,
    };

    pub fn create(allocator: std.mem.Allocator, path: []const u8) !*anyopaque {
        const self = try allocator.create(HostSource);
        self.* = .{
            .allocator = allocator,
            .base_path = try allocator.dupe(u8, path),
        };
        return self;
    }

    fn getSelf(ptr: *anyopaque) *HostSource {
        return @ptrCast(@alignCast(ptr));
    }

    fn getFullPath(self: *HostSource, rel_path: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}{s}",
            .{ self.base_path, rel_path },
        );
    }

    fn existsFn(ptr: *anyopaque, path: []const u8) bool {
        const self = getSelf(ptr);
        const full_path = self.getFullPath(path) catch return false;
        defer self.allocator.free(full_path);

        std.fs.accessAbsolute(full_path, .{}) catch return false;
        return true;
    }

    fn readFn(ptr: *anyopaque, path: []const u8) ?[]const u8 {
        const self = getSelf(ptr);
        const full_path = self.getFullPath(path) catch return null;
        defer self.allocator.free(full_path);

        const file = std.fs.openFileAbsolute(full_path, .{}) catch return null;
        defer file.close();

        const stat = file.stat() catch return null;
        const content = self.allocator.alloc(u8, @intCast(stat.size)) catch return null;
        _ = file.readAll(content) catch {
            self.allocator.free(content);
            return null;
        };

        return content;
    }

    fn listFn(ptr: *anyopaque, path: []const u8, allocator: std.mem.Allocator) ?[][]const u8 {
        const self = getSelf(ptr);
        const full_path = self.getFullPath(path) catch return null;
        defer self.allocator.free(full_path);

        var dir = std.fs.openDirAbsolute(full_path, .{ .iterate = true }) catch return null;
        defer dir.close();

        var entries = std.ArrayList([]const u8).init(allocator);
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            entries.append(allocator.dupe(u8, entry.name) catch continue) catch continue;
        }

        return entries.toOwnedSlice() catch null;
    }

    fn statFn(ptr: *anyopaque, path: []const u8) ?types.StatInfo {
        const self = getSelf(ptr);
        const full_path = self.getFullPath(path) catch return null;
        defer self.allocator.free(full_path);

        const stat = std.fs.cwd().statFile(full_path) catch return null;

        return .{
            .mode = @truncate(stat.mode),
            .size = stat.size,
            .is_dir = stat.kind == .directory,
            .is_symlink = stat.kind == .sym_link,
        };
    }

    fn deinitFn(ptr: *anyopaque) void {
        const self = getSelf(ptr);
        self.allocator.free(self.base_path);
        self.allocator.destroy(self);
    }
};

test "HostSource exists" {
    const allocator = std.testing.allocator;

    const impl = try HostSource.create(allocator, "/tmp");
    defer HostSource.vtable.deinit(impl);

    // /tmp should exist
    try std.testing.expect(HostSource.vtable.exists(impl, ""));
}
