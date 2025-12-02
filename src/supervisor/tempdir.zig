//! Temporary directory management for trace buffers
//!
//! Creates and manages the temporary directory structure used for
//! inter-process trace buffer communication.

const std = @import("std");

/// Temporary directory state
pub const TempDir = struct {
    allocator: std.mem.Allocator,
    base_path: []u8,
    traces_dir: []u8,

    /// Initialize temporary directory structure
    pub fn init(allocator: std.mem.Allocator, base_tmp: []const u8) !TempDir {
        // Generate unique temp directory name
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        const random = prng.random();
        const random_suffix = random.int(u64);

        // Create base path
        const base_path = try std.fmt.allocPrint(
            allocator,
            "{s}/uwrx-{x}",
            .{ base_tmp, random_suffix },
        );
        errdefer allocator.free(base_path);

        // Create traces subdirectory path
        const traces_dir = try std.fmt.allocPrint(
            allocator,
            "{s}/traces",
            .{base_path},
        );
        errdefer allocator.free(traces_dir);

        // Create directories
        std.fs.makeDirAbsolute(base_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.makeDirAbsolute(traces_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return .{
            .allocator = allocator,
            .base_path = base_path,
            .traces_dir = traces_dir,
        };
    }

    pub fn deinit(self: *TempDir) void {
        // Clean up temp directory
        std.fs.deleteTreeAbsolute(self.base_path) catch {};
        self.allocator.free(self.traces_dir);
        self.allocator.free(self.base_path);
    }

    /// Get path for a process trace file
    pub fn getTracePath(self: *const TempDir, allocator: std.mem.Allocator, pid: std.os.linux.pid_t) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{s}/{d}",
            .{ self.traces_dir, pid },
        );
    }
};

test "TempDir init and cleanup" {
    const allocator = std.testing.allocator;

    var temp = try TempDir.init(allocator, "/tmp");
    defer temp.deinit();

    // Verify directories exist
    var dir = try std.fs.openDirAbsolute(temp.traces_dir, .{});
    dir.close();
}
