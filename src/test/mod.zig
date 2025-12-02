//! Integrated test framework for uwrx
//!
//! Provides self-contained tests that verify all uwrx functionality.
//! Tests include necessary helper programs and can run standalone.

const std = @import("std");
const builtin = @import("builtin");

pub const runner = @import("runner.zig");
pub const helpers = @import("helpers.zig");
pub const cases = @import("cases.zig");

/// Test result
pub const TestResult = struct {
    name: []const u8,
    passed: bool,
    duration_ns: u64,
    message: ?[]const u8 = null,
    stdout: ?[]const u8 = null,
    stderr: ?[]const u8 = null,
};

/// Test suite
pub const TestSuite = struct {
    allocator: std.mem.Allocator,
    results: std.ArrayList(TestResult),
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,

    pub fn init(allocator: std.mem.Allocator) TestSuite {
        return .{
            .allocator = allocator,
            .results = std.ArrayList(TestResult).init(allocator),
        };
    }

    pub fn deinit(self: *TestSuite) void {
        for (self.results.items) |result| {
            if (result.message) |m| self.allocator.free(m);
            if (result.stdout) |s| self.allocator.free(s);
            if (result.stderr) |s| self.allocator.free(s);
        }
        self.results.deinit();
    }

    pub fn addResult(self: *TestSuite, result: TestResult) !void {
        try self.results.append(result);
        if (result.passed) {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
    }

    pub fn printSummary(self: *const TestSuite) void {
        std.debug.print("\n" ++ "=" ** 60 ++ "\n", .{});
        std.debug.print("Test Summary\n", .{});
        std.debug.print("=" ** 60 ++ "\n", .{});

        for (self.results.items) |result| {
            const status = if (result.passed) "\x1b[32mPASS\x1b[0m" else "\x1b[31mFAIL\x1b[0m";
            const duration_ms = @as(f64, @floatFromInt(result.duration_ns)) / 1_000_000.0;
            std.debug.print("[{s}] {s} ({d:.2}ms)\n", .{ status, result.name, duration_ms });

            if (!result.passed) {
                if (result.message) |msg| {
                    std.debug.print("       Message: {s}\n", .{msg});
                }
                if (result.stderr) |stderr| {
                    if (stderr.len > 0 and stderr.len < 500) {
                        std.debug.print("       Stderr: {s}\n", .{stderr});
                    }
                }
            }
        }

        std.debug.print("\n", .{});
        std.debug.print("Total: {d} passed, {d} failed, {d} skipped\n", .{
            self.passed,
            self.failed,
            self.skipped,
        });

        if (self.failed == 0) {
            std.debug.print("\x1b[32mAll tests passed!\x1b[0m\n", .{});
        } else {
            std.debug.print("\x1b[31mSome tests failed.\x1b[0m\n", .{});
        }
    }
};

/// Run all tests
pub fn runAll(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var suite = TestSuite.init(allocator);
    defer suite.deinit();

    // Parse test arguments
    var filter: ?[]const u8 = null;
    var verbose = false;
    var i: usize = 2; // Skip "uwrx" and "test"

    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-v") or std.mem.eql(u8, args[i], "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, args[i], "-f") or std.mem.eql(u8, args[i], "--filter")) {
            i += 1;
            if (i < args.len) {
                filter = args[i];
            }
        } else if (std.mem.eql(u8, args[i], "-l") or std.mem.eql(u8, args[i], "--list")) {
            cases.listTests();
            return 0;
        } else if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
            printTestHelp();
            return 0;
        }
    }

    std.debug.print("uwrx integrated test suite\n", .{});
    std.debug.print("-" ** 60 ++ "\n\n", .{});

    // Run tests
    try cases.runTests(allocator, &suite, filter, verbose);

    suite.printSummary();

    return if (suite.failed > 0) 1 else 0;
}

fn printTestHelp() void {
    const help =
        \\uwrx test - Run integrated test suite
        \\
        \\USAGE:
        \\    uwrx test [options]
        \\
        \\OPTIONS:
        \\    -v, --verbose       Verbose output
        \\    -f, --filter <pat>  Only run tests matching pattern
        \\    -l, --list          List available tests
        \\    -h, --help          Show this help
        \\
        \\EXAMPLES:
        \\    uwrx test                   Run all tests
        \\    uwrx test -f filesystem     Run filesystem tests only
        \\    uwrx test -v                Run with verbose output
        \\    uwrx test -l                List all available tests
        \\
    ;
    std.debug.print("{s}", .{help});
}

test {
    _ = runner;
    _ = helpers;
    _ = cases;
}
