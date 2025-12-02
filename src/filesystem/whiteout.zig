//! Whiteout handling for file deletions
//!
//! Uses character device 0/0 as whiteout markers, compatible with overlayfs.

const std = @import("std");
const linux = std.os.linux;

/// Whiteout device numbers (major 0, minor 0)
pub const WHITEOUT_DEV_MAJOR: u32 = 0;
pub const WHITEOUT_DEV_MINOR: u32 = 0;

/// Create a whiteout file at the given path
pub fn createWhiteout(path: []const u8) !void {
    // Character device with major/minor 0/0
    const dev: linux.dev_t = makedev(WHITEOUT_DEV_MAJOR, WHITEOUT_DEV_MINOR);

    const path_c = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_c);

    const result = linux.mknod(path_c, linux.S.IFCHR | 0o000, dev);
    if (result != 0) {
        return error.MknodFailed;
    }
}

/// Check if a path is a whiteout file
pub fn isWhiteout(base_path: []const u8, rel_path: []const u8) bool {
    var path_buf: [4096]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{ base_path, rel_path }) catch return false;

    return isWhiteoutPath(full_path);
}

/// Check if a specific path is a whiteout file
pub fn isWhiteoutPath(path: []const u8) bool {
    var stat_buf: linux.Stat = undefined;

    const path_c = std.heap.page_allocator.dupeZ(u8, path) catch return false;
    defer std.heap.page_allocator.free(path_c);

    const result = linux.lstat(path_c, &stat_buf);
    if (result != 0) {
        return false;
    }

    // Check if it's a character device with major/minor 0/0
    if ((stat_buf.mode & linux.S.IFMT) != linux.S.IFCHR) {
        return false;
    }

    const major_num = major(stat_buf.rdev);
    const minor_num = minor(stat_buf.rdev);

    return major_num == WHITEOUT_DEV_MAJOR and minor_num == WHITEOUT_DEV_MINOR;
}

/// Check if a filename indicates a whiteout (alternative method)
/// Some systems use ".wh." prefix for whiteouts
pub fn isWhiteoutName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, ".wh.");
}

/// Get original name from whiteout name
pub fn getOriginalName(name: []const u8) []const u8 {
    if (std.mem.startsWith(u8, name, ".wh.")) {
        return name[4..];
    }
    return name;
}

/// Get whiteout name for a file
pub fn getWhiteoutName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".wh.{s}", .{name});
}

/// Delete a file by creating a whiteout
pub fn deleteFile(files_dir: []const u8, path: []const u8, pid: u32) !void {
    var whiteout_path_buf: [4096]u8 = undefined;
    const whiteout_path = std.fmt.bufPrint(&whiteout_path_buf, "{s}-{d}{s}", .{ files_dir, pid, path }) catch return error.PathTooLong;

    // Create parent directories if needed
    if (std.fs.path.dirname(whiteout_path)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    try createWhiteout(whiteout_path);
}

/// Remove a whiteout (resurrect a file)
pub fn removeWhiteout(path: []const u8) !void {
    try std.fs.deleteFileAbsolute(path);
}

// Linux device number helpers
fn makedev(major_num: u32, minor_num: u32) linux.dev_t {
    return (@as(linux.dev_t, major_num) << 8) | @as(linux.dev_t, minor_num);
}

fn major(dev: linux.dev_t) u32 {
    return @truncate((dev >> 8) & 0xfff);
}

fn minor(dev: linux.dev_t) u32 {
    return @truncate(dev & 0xff);
}

test "whiteout name handling" {
    try std.testing.expect(isWhiteoutName(".wh.deleted_file"));
    try std.testing.expect(!isWhiteoutName("normal_file"));

    try std.testing.expectEqualStrings("deleted_file", getOriginalName(".wh.deleted_file"));
}

test "getWhiteoutName" {
    const allocator = std.testing.allocator;
    const name = try getWhiteoutName(allocator, "test.txt");
    defer allocator.free(name);
    try std.testing.expectEqualStrings(".wh.test.txt", name);
}
