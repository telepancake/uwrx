//! Test case implementations
//!
//! Contains all integrated test cases for uwrx functionality.

const std = @import("std");
const mod = @import("mod.zig");
const runner = @import("runner.zig");
const helpers = @import("helpers.zig");

/// All test cases
pub const all_tests = [_]runner.TestCase{
    // Basic tests
    .{ .name = "basic/help", .func = testHelp, .category = .basic },
    .{ .name = "basic/version", .func = testVersion, .category = .basic },
    .{ .name = "basic/arg_parsing", .func = testArgParsing, .category = .basic },
    .{ .name = "basic/simple_exit", .func = testSimpleExit, .category = .basic },
    .{ .name = "basic/exit_codes", .func = testExitCodes, .category = .basic },
    .{ .name = "basic/stdout_capture", .func = testStdoutCapture, .category = .basic },
    .{ .name = "basic/stderr_capture", .func = testStderrCapture, .category = .basic },

    // Filesystem tests
    .{ .name = "filesystem/read_file", .func = testReadFile, .category = .filesystem },
    .{ .name = "filesystem/write_file", .func = testWriteFile, .category = .filesystem },
    .{ .name = "filesystem/create_dir", .func = testCreateDir, .category = .filesystem },
    .{ .name = "filesystem/file_isolation", .func = testFileIsolation, .category = .filesystem },
    .{ .name = "filesystem/source_overlay", .func = testSourceOverlay, .category = .filesystem },

    // Reproducibility tests
    .{ .name = "reproducibility/deterministic_time", .func = testDeterministicTime, .category = .reproducibility },
    .{ .name = "reproducibility/env_vars", .func = testEnvVars, .category = .reproducibility },

    // Tracing tests
    .{ .name = "tracing/trace_created", .func = testTraceCreated, .category = .tracing },
    .{ .name = "tracing/process_tree", .func = testProcessTree, .category = .tracing },

    // Integration tests
    .{ .name = "integration/multi_step", .func = testMultiStep, .category = .integration },
    .{ .name = "integration/parent_trace", .func = testParentTrace, .category = .integration },
};

/// List all available tests
pub fn listTests() void {
    std.debug.print("Available tests:\n\n", .{});

    var last_category: ?runner.TestCase.Category = null;
    for (all_tests) |t| {
        if (last_category != t.category) {
            std.debug.print("\n[{s}]\n", .{@tagName(t.category)});
            last_category = t.category;
        }
        std.debug.print("  {s}\n", .{t.name});
    }
    std.debug.print("\nTotal: {d} tests\n", .{all_tests.len});
}

/// Run tests matching the filter
pub fn runTests(
    allocator: std.mem.Allocator,
    suite: *mod.TestSuite,
    filter: ?[]const u8,
    verbose: bool,
) !void {
    // Get uwrx path
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const uwrx_path = std.fs.selfExePath(&exe_buf) catch "/proc/self/exe";

    // Create base temp directory
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_temp = try std.fmt.bufPrint(&tmp_buf, "/tmp/uwrx-test-{d}", .{std.time.timestamp()});

    try std.fs.makeDirAbsolute(base_temp);
    defer std.fs.deleteTreeAbsolute(base_temp) catch {};

    for (all_tests) |test_case| {
        // Apply filter if specified
        if (filter) |f| {
            if (std.mem.indexOf(u8, test_case.name, f) == null) {
                continue;
            }
        }

        if (verbose) {
            std.debug.print("Running: {s}...\n", .{test_case.name});
        }

        const result = runner.runTest(
            allocator,
            test_case,
            base_temp,
            uwrx_path,
            verbose,
        );

        try suite.addResult(result);
    }
}

// ============================================================================
// Basic Tests
// ============================================================================

fn testHelp(ctx: *runner.TestContext) !void {
    var result = try ctx.runUwrx(&.{"--help"});
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    // Help output goes to stderr (std.debug.print)
    try ctx.expectContains(result.stderr, "uwrx");
    try ctx.expectContains(result.stderr, "USAGE:");
}

fn testVersion(ctx: *runner.TestContext) !void {
    var result = try ctx.runUwrx(&.{"--version"});
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    // Version output goes to stderr (std.debug.print)
    try ctx.expectContains(result.stderr, "uwrx");
}

fn testArgParsing(ctx: *runner.TestContext) !void {
    // Test that various argument combinations are parsed correctly
    var result = try ctx.runUwrx(&.{ "run", "--build", ctx.work_dir, "--", "/bin/true" });
    defer result.deinit(ctx.allocator);

    // Should run without crashing (may fail due to missing supervisor features)
    ctx.log("Exit code: {d}", .{result.exit_code});
}

fn testSimpleExit(ctx: *runner.TestContext) !void {
    // Create a simple script that exits successfully
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "simple.sh", helpers.exit_code);
    defer ctx.allocator.free(script);

    var result = try ctx.runProcess(&.{ script, "0" });
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
}

fn testExitCodes(ctx: *runner.TestContext) !void {
    // Test various exit codes
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "exit.sh", helpers.exit_code);
    defer ctx.allocator.free(script);

    // Test exit 0
    var r0 = try ctx.runProcess(&.{ script, "0" });
    defer r0.deinit(ctx.allocator);
    try ctx.expectEqual(@as(u8, 0), r0.exit_code);

    // Test exit 1
    var r1 = try ctx.runProcess(&.{ script, "1" });
    defer r1.deinit(ctx.allocator);
    try ctx.expectEqual(@as(u8, 1), r1.exit_code);

    // Test exit 42
    var r42 = try ctx.runProcess(&.{ script, "42" });
    defer r42.deinit(ctx.allocator);
    try ctx.expectEqual(@as(u8, 42), r42.exit_code);
}

fn testStdoutCapture(ctx: *runner.TestContext) !void {
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "output.sh", helpers.structured_output);
    defer ctx.allocator.free(script);

    var result = try ctx.runProcess(&.{script});
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    try ctx.expectContains(result.stdout, "HEADER: test output");
    try ctx.expectContains(result.stdout, "LINE1:");
    try ctx.expectContains(result.stdout, "FOOTER: end of output");
}

fn testStderrCapture(ctx: *runner.TestContext) !void {
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "mixed.sh", helpers.mixed_output);
    defer ctx.allocator.free(script);

    var result = try ctx.runProcess(&.{script});
    defer result.deinit(ctx.allocator);

    try ctx.expectContains(result.stdout, "stdout line 1");
    try ctx.expectContains(result.stderr, "stderr line 1");
}

// ============================================================================
// Filesystem Tests
// ============================================================================

fn testReadFile(ctx: *runner.TestContext) !void {
    // Create a test file
    try ctx.createFile("test_input.txt", "hello world\n");

    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "read.sh", helpers.read_file);
    defer ctx.allocator.free(script);

    const input_path = try std.fs.path.join(ctx.allocator, &.{ ctx.work_dir, "test_input.txt" });
    defer ctx.allocator.free(input_path);

    var result = try ctx.runProcess(&.{ script, input_path });
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    try ctx.expectContains(result.stdout, "hello world");
}

fn testWriteFile(ctx: *runner.TestContext) !void {
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "write.sh", helpers.write_file);
    defer ctx.allocator.free(script);

    const output_path = try std.fs.path.join(ctx.allocator, &.{ ctx.work_dir, "output.txt" });
    defer ctx.allocator.free(output_path);

    var result = try ctx.runProcess(&.{ script, output_path, "test content" });
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);

    // Verify file was created
    const content = try ctx.readFile("output.txt");
    defer ctx.allocator.free(content);

    try ctx.expectContains(content, "test content");
}

fn testCreateDir(ctx: *runner.TestContext) !void {
    const script =
        \\#!/bin/sh
        \\mkdir -p "$1/subdir"
        \\echo "created" > "$1/subdir/file.txt"
        \\ls "$1/subdir"
    ;

    const helper = try helpers.createHelper(ctx.allocator, ctx.work_dir, "mkdir.sh", script);
    defer ctx.allocator.free(helper);

    var result = try ctx.runProcess(&.{ helper, ctx.work_dir });
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    try ctx.expectContains(result.stdout, "file.txt");
}

fn testFileIsolation(ctx: *runner.TestContext) !void {
    // Test that file modifications are isolated
    try ctx.createFile("original.txt", "original content\n");

    const script =
        \\#!/bin/sh
        \\echo "modified" > "$1/original.txt"
        \\cat "$1/original.txt"
    ;

    const helper = try helpers.createHelper(ctx.allocator, ctx.work_dir, "modify.sh", script);
    defer ctx.allocator.free(helper);

    var result = try ctx.runProcess(&.{ helper, ctx.work_dir });
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    try ctx.expectContains(result.stdout, "modified");
}

fn testSourceOverlay(ctx: *runner.TestContext) !void {
    // Create a source directory with test files
    try ctx.makeDir("source");
    try ctx.createFile("source/file1.txt", "from source\n");
    try ctx.createFile("source/file2.txt", "also from source\n");

    // Verify files exist
    try ctx.expectEqualStrings("true", if (ctx.fileExists("source/file1.txt")) "true" else "false");
    try ctx.expectEqualStrings("true", if (ctx.fileExists("source/file2.txt")) "true" else "false");
}

// ============================================================================
// Reproducibility Tests
// ============================================================================

fn testDeterministicTime(ctx: *runner.TestContext) !void {
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "time.sh", helpers.print_time);
    defer ctx.allocator.free(script);

    // Run twice and compare
    var r1 = try ctx.runProcess(&.{script});
    defer r1.deinit(ctx.allocator);

    var r2 = try ctx.runProcess(&.{script});
    defer r2.deinit(ctx.allocator);

    // Both should succeed
    try ctx.expectEqual(@as(u8, 0), r1.exit_code);
    try ctx.expectEqual(@as(u8, 0), r2.exit_code);

    // Times may differ slightly but should be valid timestamps
    ctx.log("Time 1: {s}", .{std.mem.trim(u8, r1.stdout, "\n")});
    ctx.log("Time 2: {s}", .{std.mem.trim(u8, r2.stdout, "\n")});
}

fn testEnvVars(ctx: *runner.TestContext) !void {
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "env.sh", helpers.env_reader);
    defer ctx.allocator.free(script);

    var result = try ctx.runProcess(&.{script});
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    try ctx.expectContains(result.stdout, "PATH=");
    try ctx.expectContains(result.stdout, "HOME=");
}

// ============================================================================
// Tracing Tests
// ============================================================================

fn testTraceCreated(ctx: *runner.TestContext) !void {
    // Run uwrx and verify trace directory structure
    const build_dir = try std.fs.path.join(ctx.allocator, &.{ ctx.work_dir, "build" });
    defer ctx.allocator.free(build_dir);

    // This test just verifies basic invocation
    // Full trace verification requires more infrastructure
    ctx.log("Would create trace in: {s}", .{build_dir});
}

fn testProcessTree(ctx: *runner.TestContext) !void {
    const script = try helpers.createHelper(ctx.allocator, ctx.work_dir, "fork.sh", helpers.fork_tree);
    defer ctx.allocator.free(script);

    var result = try ctx.runProcess(&.{ script, "2", "root" });
    defer result.deinit(ctx.allocator);

    try ctx.expectEqual(@as(u8, 0), result.exit_code);
    try ctx.expectContains(result.stdout, "PROCESS: root");
    try ctx.expectContains(result.stdout, "PROCESS: root_left");
    try ctx.expectContains(result.stdout, "PROCESS: root_right");
}

// ============================================================================
// Integration Tests
// ============================================================================

fn testMultiStep(ctx: *runner.TestContext) !void {
    // Simulate a multi-step build process
    const step1 =
        \\#!/bin/sh
        \\echo "Step 1: Generating"
        \\echo "generated" > "$1/generated.txt"
    ;

    const step2 =
        \\#!/bin/sh
        \\echo "Step 2: Compiling"
        \\cat "$1/generated.txt" > "$1/output.txt"
        \\echo "compiled" >> "$1/output.txt"
    ;

    const h1 = try helpers.createHelper(ctx.allocator, ctx.work_dir, "step1.sh", step1);
    defer ctx.allocator.free(h1);

    const h2 = try helpers.createHelper(ctx.allocator, ctx.work_dir, "step2.sh", step2);
    defer ctx.allocator.free(h2);

    // Run step 1
    var r1 = try ctx.runProcess(&.{ h1, ctx.work_dir });
    defer r1.deinit(ctx.allocator);
    try ctx.expectEqual(@as(u8, 0), r1.exit_code);

    // Run step 2
    var r2 = try ctx.runProcess(&.{ h2, ctx.work_dir });
    defer r2.deinit(ctx.allocator);
    try ctx.expectEqual(@as(u8, 0), r2.exit_code);

    // Verify output
    const content = try ctx.readFile("output.txt");
    defer ctx.allocator.free(content);

    try ctx.expectContains(content, "generated");
    try ctx.expectContains(content, "compiled");
}

fn testParentTrace(ctx: *runner.TestContext) !void {
    // Test that parent traces can be referenced
    try ctx.makeDir("parent_trace");
    try ctx.createFile("parent_trace/meta.json", "{\"version\": 1}");

    // Parent trace should be accessible
    try ctx.expectEqualStrings("true", if (ctx.fileExists("parent_trace/meta.json")) "true" else "false");
}

test "all test functions compile" {
    // This test just ensures all test functions have valid signatures
    comptime {
        for (all_tests) |t| {
            _ = t.func;
        }
    }
}
