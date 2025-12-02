//! Test runner utilities
//!
//! Provides infrastructure for running individual tests with proper
//! setup, teardown, and isolation.

const std = @import("std");
const mod = @import("mod.zig");

/// Test function signature
pub const TestFn = *const fn (ctx: *TestContext) anyerror!void;

/// Test context passed to each test
pub const TestContext = struct {
    allocator: std.mem.Allocator,
    temp_dir: []const u8,
    verbose: bool,
    /// Working directory for this test
    work_dir: []const u8,
    /// Path to uwrx executable
    uwrx_path: []const u8,

    /// Run uwrx with given arguments
    pub fn runUwrx(self: *TestContext, args: []const []const u8) !ProcessResult {
        var full_args = std.ArrayList([]const u8).init(self.allocator);
        defer full_args.deinit();

        try full_args.append(self.uwrx_path);
        for (args) |arg| {
            try full_args.append(arg);
        }

        return self.runProcess(full_args.items);
    }

    /// Run an arbitrary process
    pub fn runProcess(self: *TestContext, argv: []const []const u8) !ProcessResult {
        var child = std.process.Child.init(argv, self.allocator);
        child.cwd = self.work_dir;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        const stdout = try child.stdout.?.reader().readAllAlloc(self.allocator, 10 * 1024 * 1024);
        errdefer self.allocator.free(stdout);

        const stderr = try child.stderr.?.reader().readAllAlloc(self.allocator, 10 * 1024 * 1024);
        errdefer self.allocator.free(stderr);

        const term = try child.wait();

        return .{
            .stdout = stdout,
            .stderr = stderr,
            .exit_code = switch (term) {
                .Exited => |code| code,
                else => 255,
            },
        };
    }

    /// Create a file in the work directory
    pub fn createFile(self: *TestContext, rel_path: []const u8, content: []const u8) !void {
        const full_path = try std.fs.path.join(self.allocator, &.{ self.work_dir, rel_path });
        defer self.allocator.free(full_path);

        // Create parent directories if needed
        if (std.fs.path.dirname(full_path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        const file = try std.fs.createFileAbsolute(full_path, .{});
        defer file.close();
        try file.writeAll(content);
    }

    /// Read a file from the work directory
    pub fn readFile(self: *TestContext, rel_path: []const u8) ![]u8 {
        const full_path = try std.fs.path.join(self.allocator, &.{ self.work_dir, rel_path });
        defer self.allocator.free(full_path);

        return std.fs.cwd().readFileAlloc(self.allocator, full_path, 10 * 1024 * 1024);
    }

    /// Check if a file exists
    pub fn fileExists(self: *TestContext, rel_path: []const u8) bool {
        const full_path = std.fs.path.join(self.allocator, &.{ self.work_dir, rel_path }) catch return false;
        defer self.allocator.free(full_path);

        std.fs.accessAbsolute(full_path, .{}) catch return false;
        return true;
    }

    /// Create a directory
    pub fn makeDir(self: *TestContext, rel_path: []const u8) !void {
        const full_path = try std.fs.path.join(self.allocator, &.{ self.work_dir, rel_path });
        defer self.allocator.free(full_path);

        try std.fs.makeDirAbsolute(full_path);
    }

    /// Assert equality
    pub fn expectEqual(self: *TestContext, expected: anytype, actual: @TypeOf(expected)) !void {
        _ = self;
        if (expected != actual) {
            return error.AssertionFailed;
        }
    }

    /// Assert string equality
    pub fn expectEqualStrings(self: *TestContext, expected: []const u8, actual: []const u8) !void {
        _ = self;
        if (!std.mem.eql(u8, expected, actual)) {
            return error.AssertionFailed;
        }
    }

    /// Assert string contains
    pub fn expectContains(self: *TestContext, haystack: []const u8, needle: []const u8) !void {
        _ = self;
        if (std.mem.indexOf(u8, haystack, needle) == null) {
            return error.AssertionFailed;
        }
    }

    /// Log a message (only in verbose mode)
    pub fn log(self: *TestContext, comptime fmt: []const u8, args: anytype) void {
        if (self.verbose) {
            std.debug.print("  [LOG] " ++ fmt ++ "\n", args);
        }
    }
};

/// Process execution result
pub const ProcessResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    exit_code: u8,

    pub fn deinit(self: *ProcessResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

/// Test case definition
pub const TestCase = struct {
    name: []const u8,
    func: TestFn,
    category: Category,
    /// Whether test requires root
    requires_root: bool = false,
    /// Whether test requires network
    requires_network: bool = false,

    pub const Category = enum {
        basic,
        filesystem,
        network,
        reproducibility,
        tracing,
        bundle,
        replay,
        integration,
    };
};

/// Run a single test case
pub fn runTest(
    allocator: std.mem.Allocator,
    test_case: TestCase,
    base_temp_dir: []const u8,
    uwrx_path: []const u8,
    verbose: bool,
) mod.TestResult {
    const start = std.time.nanoTimestamp();

    // Check prerequisites
    if (test_case.requires_root) {
        if (std.os.linux.getuid() != 0) {
            return .{
                .name = test_case.name,
                .passed = true, // Skip counts as pass
                .duration_ns = 0,
                .message = allocator.dupe(u8, "Skipped: requires root") catch null,
            };
        }
    }

    // Create test-specific temp directory (replace / with _ in name)
    var safe_name: [256]u8 = undefined;
    var safe_len: usize = 0;
    for (test_case.name) |c| {
        if (safe_len >= safe_name.len - 1) break;
        safe_name[safe_len] = if (c == '/') '_' else c;
        safe_len += 1;
    }

    const test_dir = std.fmt.allocPrint(allocator, "{s}/{s}", .{
        base_temp_dir,
        safe_name[0..safe_len],
    }) catch {
        return .{
            .name = test_case.name,
            .passed = false,
            .duration_ns = 0,
            .message = allocator.dupe(u8, "Failed to allocate test directory") catch null,
        };
    };
    defer allocator.free(test_dir);

    std.fs.makeDirAbsolute(test_dir) catch |err| {
        return .{
            .name = test_case.name,
            .passed = false,
            .duration_ns = 0,
            .message = std.fmt.allocPrint(allocator, "Failed to create test dir: {}", .{err}) catch null,
        };
    };
    defer std.fs.deleteTreeAbsolute(test_dir) catch {};

    // Create context
    var ctx = TestContext{
        .allocator = allocator,
        .temp_dir = base_temp_dir,
        .work_dir = test_dir,
        .uwrx_path = uwrx_path,
        .verbose = verbose,
    };

    // Run the test
    if (test_case.func(&ctx)) {
        const end = std.time.nanoTimestamp();
        return .{
            .name = test_case.name,
            .passed = true,
            .duration_ns = @intCast(end - start),
        };
    } else |err| {
        const end = std.time.nanoTimestamp();
        return .{
            .name = test_case.name,
            .passed = false,
            .duration_ns = @intCast(end - start),
            .message = std.fmt.allocPrint(allocator, "Error: {}", .{err}) catch null,
        };
    }
}

test "TestContext file operations" {
    const allocator = std.testing.allocator;

    // Create a temp dir for testing
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try std.fs.realpath("/tmp", &tmp_buf);

    var ctx = TestContext{
        .allocator = allocator,
        .temp_dir = tmp_path,
        .work_dir = tmp_path,
        .uwrx_path = "/bin/true",
        .verbose = false,
    };

    // Test file creation and reading
    try ctx.createFile("test_runner_test.txt", "hello world");
    defer std.fs.deleteFileAbsolute("/tmp/test_runner_test.txt") catch {};

    const content = try ctx.readFile("test_runner_test.txt");
    defer allocator.free(content);

    try std.testing.expectEqualStrings("hello world", content);
}
