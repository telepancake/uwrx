//! CLI inspection commands
//!
//! Provides command-line tools for examining traces.

const std = @import("std");
const storage = @import("../tracing/storage.zig");
const meta = @import("../filesystem/meta.zig");

/// Run CLI inspection
pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 3) {
        printHelp();
        return;
    }

    const subcommand = args[2];

    if (std.mem.eql(u8, subcommand, "files")) {
        try runFiles(allocator, args);
    } else if (std.mem.eql(u8, subcommand, "procs")) {
        try runProcs(allocator, args);
    } else if (std.mem.eql(u8, subcommand, "output")) {
        try runOutput(allocator, args);
    } else if (std.mem.eql(u8, subcommand, "events")) {
        try runEvents(allocator, args);
    } else {
        printHelp();
    }
}

fn printHelp() void {
    const help =
        \\uwrx inspect - Trace inspection commands
        \\
        \\USAGE:
        \\    uwrx inspect <command> <trace-path> [options]
        \\
        \\COMMANDS:
        \\    files <trace>           List modified files
        \\        --who               Show which process modified each file
        \\        --by-pid <pid>      List files modified by specific process
        \\
        \\    procs <trace>           List processes
        \\        --tree              Show process tree
        \\
        \\    output <trace> [pid]    Show stdout/stderr
        \\
        \\    events <trace>          List raw events
        \\        --limit <n>         Limit output
        \\        --type <type>       Filter by event type
        \\
        \\OPTIONS:
        \\    --json                  Output in JSON format
        \\
    ;
    std.debug.print("{s}", .{help});
}

/// List modified files
fn runFiles(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("Error: Missing trace path\n", .{});
        return;
    }

    const trace_path = args[3];
    var show_who = false;
    var filter_pid: ?u32 = null;
    var json_output = false;

    var i: usize = 4;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--who")) {
            show_who = true;
        } else if (std.mem.eql(u8, args[i], "--by-pid")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --by-pid requires argument\n", .{});
                return;
            }
            filter_pid = std.fmt.parseInt(u32, args[i], 10) catch {
                std.debug.print("Error: Invalid PID\n", .{});
                return;
            };
        } else if (std.mem.eql(u8, args[i], "--json")) {
            json_output = true;
        }
    }

    // Scan trace for files
    var tracker = meta.scanTraceFiles(allocator, trace_path) catch |err| {
        std.debug.print("Error scanning trace: {}\n", .{err});
        return;
    };
    defer tracker.deinit();

    const files = tracker.getAllFiles();
    defer allocator.free(files);

    if (json_output) {
        std.debug.print("[\n", .{});
        for (files, 0..) |file, idx| {
            const comma: []const u8 = if (idx > 0) "," else "";
            if (show_who) {
                const info = tracker.known_files.get(file);
                const pid = if (info) |p| p else 0;
                std.debug.print("{s}  {{\"path\": \"{s}\", \"pid\": {d}}}\n", .{ comma, file, pid });
            } else {
                std.debug.print("{s}  \"{s}\"\n", .{ comma, file });
            }
        }
        std.debug.print("]\n", .{});
    } else {
        for (files) |file| {
            if (filter_pid) |pid| {
                if (tracker.getProcessFiles(pid)) |process_files| {
                    if (!process_files.contains(file)) continue;
                } else continue;
            }

            if (show_who) {
                const info = tracker.known_files.get(file);
                const pid = if (info) |p| p else 0;
                std.debug.print("{s}\t(pid {d})\n", .{ file, pid });
            } else {
                std.debug.print("{s}\n", .{file});
            }
        }
    }
}

/// List processes
fn runProcs(_: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("Error: Missing trace path\n", .{});
        return;
    }

    const trace_path = args[3];
    var show_tree = false;

    var i: usize = 4;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--tree")) {
            show_tree = true;
        }
    }

    // Load and parse trace (not yet implemented)
    std.debug.print("Process listing not yet implemented for {s} (tree={any})\n", .{ trace_path, show_tree });
}

/// Show output
fn runOutput(_: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("Error: Missing trace path\n", .{});
        return;
    }

    const trace_path = args[3];
    var filter_pid: ?u32 = null;

    if (args.len > 4) {
        filter_pid = std.fmt.parseInt(u32, args[4], 10) catch null;
    }

    std.debug.print("Output display not yet implemented for {s} (pid={any})\n", .{ trace_path, filter_pid });
}

/// List events
fn runEvents(_: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 4) {
        std.debug.print("Error: Missing trace path\n", .{});
        return;
    }

    const trace_path = args[3];

    std.debug.print("Event listing not yet implemented for {s}\n", .{trace_path});
}

test "CLI help" {
    printHelp();
}
