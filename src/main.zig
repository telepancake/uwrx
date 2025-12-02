//! UWRX - Process supervision and tracing tool
//!
//! A tool for running processes under supervision with syscall interception,
//! trace capture, network isolation, and reproducible builds support.

const std = @import("std");
const builtin = @import("builtin");

// Module imports
pub const util = @import("util/mod.zig");
pub const supervisor = @import("supervisor/mod.zig");
pub const manager = @import("manager/mod.zig");
pub const tracing = @import("tracing/mod.zig");
pub const network = @import("network/mod.zig");
pub const filesystem = @import("filesystem/mod.zig");
pub const sources = @import("sources/mod.zig");
pub const reproducibility = @import("reproducibility/mod.zig");
pub const rebuild = @import("rebuild/mod.zig");
pub const inspect = @import("inspect/mod.zig");
pub const bundle = @import("bundle/mod.zig");

/// Global allocator for uwrx
pub var gpa = std.heap.GeneralPurposeAllocator(.{}){};

/// Command-line options for uwrx
pub const Options = struct {
    /// Build directory location
    build_dir: []const u8 = "./build",
    /// Step name
    step: ?[]const u8 = null,
    /// Parent trace paths
    parents: std.ArrayList([]const u8),
    /// Replay trace path
    replay: ?[]const u8 = null,
    /// Network mode
    network_enabled: ?bool = null,
    /// Temporary directory location
    tmp_dir: []const u8 = "/tmp",
    /// Source mappings
    source_specs: std.ArrayList(SourceSpec),
    /// Command to execute
    command: []const []const u8 = &.{},
    /// Verbose output
    verbose: bool = false,

    pub fn init(allocator: std.mem.Allocator) Options {
        return .{
            .parents = std.ArrayList([]const u8).init(allocator),
            .source_specs = std.ArrayList(SourceSpec).init(allocator),
        };
    }

    pub fn deinit(self: *Options) void {
        self.parents.deinit();
        self.source_specs.deinit();
    }

    /// Get network enabled state (default based on replay mode)
    pub fn isNetworkEnabled(self: *const Options) bool {
        if (self.network_enabled) |enabled| {
            return enabled;
        }
        // Default: off for replay, on otherwise
        return self.replay == null;
    }
};

/// Source specification from command line
pub const SourceSpec = struct {
    dst: []const u8,
    priority: i32 = 0,
    source: []const u8,
};

/// Parse a source specification string
/// Format: <dst>[:<priority>]=<source>
fn parseSourceSpec(spec: []const u8) !SourceSpec {
    // Find the '=' separator
    const eq_pos = std.mem.indexOf(u8, spec, "=") orelse return error.InvalidSourceSpec;

    const dst_part = spec[0..eq_pos];
    const source = spec[eq_pos + 1 ..];

    // Parse dst and optional priority
    if (std.mem.lastIndexOf(u8, dst_part, ":")) |colon_pos| {
        const dst = dst_part[0..colon_pos];
        const priority_str = dst_part[colon_pos + 1 ..];
        const priority = std.fmt.parseInt(i32, priority_str, 10) catch return error.InvalidPriority;
        return .{ .dst = dst, .priority = priority, .source = source };
    }

    return .{ .dst = dst_part, .priority = 0, .source = source };
}

/// Command types
pub const Command = enum {
    run,
    @"test",
    ui,
    bundle_cmd,
    inspect_cmd,
    help,
    version,
};

/// Parse command-line arguments
pub fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !struct { cmd: Command, opts: Options } {
    var opts = Options.init(allocator);
    errdefer opts.deinit();

    if (args.len < 2) {
        return .{ .cmd = .help, .opts = opts };
    }

    // Check for bundled executable dispatch
    const exe_name = std.fs.path.basename(args[0]);
    if (!std.mem.eql(u8, exe_name, "uwrx")) {
        // Invoked via symlink - run bundled executable
        if (bundle.lookup.findBundled(exe_name)) |_| {
            // Run without supervision (direct execution)
            opts.command = args;
            return .{ .cmd = .run, .opts = opts };
        }
    }

    var cmd: Command = .help;
    var i: usize = 1;

    // Parse command
    if (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "run")) {
            cmd = .run;
            i += 1;
        } else if (std.mem.eql(u8, arg, "test")) {
            cmd = .@"test";
            i += 1;
        } else if (std.mem.eql(u8, arg, "ui")) {
            cmd = .ui;
            i += 1;
        } else if (std.mem.eql(u8, arg, "bundle")) {
            cmd = .bundle_cmd;
            i += 1;
        } else if (std.mem.eql(u8, arg, "inspect")) {
            cmd = .inspect_cmd;
            i += 1;
        } else if (std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            cmd = .help;
            i += 1;
        } else if (std.mem.eql(u8, arg, "version") or std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            cmd = .version;
            i += 1;
        } else {
            // Check if it's a bundled command without 'run'
            if (bundle.lookup.findBundled(arg)) |_| {
                opts.command = args[i..];
                return .{ .cmd = .run, .opts = opts };
            }
        }
    }

    // Parse options
    while (i < args.len) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--")) {
            // Everything after -- is the command
            i += 1;
            if (i < args.len) {
                opts.command = args[i..];
            }
            break;
        } else if (std.mem.eql(u8, arg, "--build")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.build_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--step")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.step = args[i];
        } else if (std.mem.eql(u8, arg, "--parent")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            try opts.parents.append(args[i]);
        } else if (std.mem.eql(u8, arg, "--replay")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.replay = args[i];
        } else if (std.mem.eql(u8, arg, "--net")) {
            opts.network_enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-net")) {
            opts.network_enabled = false;
        } else if (std.mem.eql(u8, arg, "--tmp")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.tmp_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--source")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            const spec = try parseSourceSpec(args[i]);
            try opts.source_specs.append(spec);
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-V")) {
            opts.verbose = true;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        } else {
            // Start of command without --
            opts.command = args[i..];
            break;
        }

        i += 1;
    }

    return .{ .cmd = cmd, .opts = opts };
}

/// Print help message
fn printHelp() void {
    const help =
        \\uwrx - Process supervision and tracing tool
        \\
        \\USAGE:
        \\    uwrx <command> [options] [-- <program> [args...]]
        \\
        \\COMMANDS:
        \\    run         Supervise a command with tracing
        \\    test        Run a test case
        \\    ui          Examine a trace interactively
        \\    inspect     Inspect trace contents
        \\    bundle      Create bundled uwrx with executables
        \\    help        Show this help message
        \\    version     Show version information
        \\
        \\RUN OPTIONS:
        \\    --build <path>      Build directory (default: ./build)
        \\    --step <name>       Step name (auto-assigned if not specified)
        \\    --parent <path>     Parent trace path (repeatable)
        \\    --replay <path>     Trace to replay
        \\    --net               Enable network access (default for non-replay)
        \\    --no-net            Disable network access (default for replay)
        \\    --tmp <path>        Temp directory location (default: /tmp)
        \\    --source <spec>     Read-only source mapping (repeatable)
        \\                        Format: <dst>[:<priority>]=<source>
        \\    -V, --verbose       Verbose output
        \\
        \\SOURCE TYPES:
        \\    /path/to/dir                      Host directory
        \\    tar:/path/file.tar[:/subpath]     Tarball
        \\    git:/path/repo[:treeish]          Git repository
        \\    oci:image:tag[:/subpath]          OCI image
        \\    squashfs:/path/file[:/subpath]    Squashfs image
        \\
        \\EXAMPLES:
        \\    uwrx run -- ./configure
        \\    uwrx run --source /src=/home/user/project -- make
        \\    uwrx run --replay ./build/0/0 -- make
        \\    uwrx inspect files ./build/0/0
        \\    uwrx ui ./build/0/0
        \\
        \\BUNDLED INVOCATION:
        \\    If uwrx is symlinked as a bundled executable name (e.g., gcc),
        \\    it will run that executable directly without supervision.
        \\
    ;
    std.debug.print("{s}", .{help});
}

/// Print version
fn printVersion() void {
    std.debug.print("uwrx version 0.1.0\n", .{});
}

/// Main entry point
pub fn main() !void {
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const parsed = parseArgs(allocator, args) catch |err| {
        std.debug.print("Error parsing arguments: {}\n", .{err});
        printHelp();
        std.process.exit(1);
    };
    var opts = parsed.opts;
    defer opts.deinit();

    switch (parsed.cmd) {
        .help => printHelp(),
        .version => printVersion(),
        .run => {
            if (opts.command.len == 0) {
                std.debug.print("Error: No command specified\n", .{});
                printHelp();
                std.process.exit(1);
            }
            try supervisor.run(allocator, &opts);
        },
        .@"test" => {
            std.debug.print("Test command not yet implemented\n", .{});
        },
        .ui => {
            try inspect.runTui(allocator, &opts);
        },
        .bundle_cmd => {
            try bundle.create.run(allocator, args);
        },
        .inspect_cmd => {
            try inspect.runCli(allocator, args);
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

test "parseSourceSpec" {
    const spec1 = try parseSourceSpec("/src=/home/user/project");
    try std.testing.expectEqualStrings("/src", spec1.dst);
    try std.testing.expectEqual(@as(i32, 0), spec1.priority);
    try std.testing.expectEqualStrings("/home/user/project", spec1.source);

    const spec2 = try parseSourceSpec("/usr:-5=/nix/store/abc");
    try std.testing.expectEqualStrings("/usr", spec2.dst);
    try std.testing.expectEqual(@as(i32, -5), spec2.priority);
    try std.testing.expectEqualStrings("/nix/store/abc", spec2.source);

    const spec3 = try parseSourceSpec("/opt:50=tar:/path/sdk.tar.gz");
    try std.testing.expectEqualStrings("/opt", spec3.dst);
    try std.testing.expectEqual(@as(i32, 50), spec3.priority);
    try std.testing.expectEqualStrings("tar:/path/sdk.tar.gz", spec3.source);
}

test "parseArgs help" {
    const args = [_][]const u8{"uwrx"};
    const result = try parseArgs(std.testing.allocator, &args);
    var opts = result.opts;
    defer opts.deinit();
    try std.testing.expectEqual(Command.help, result.cmd);
}

test "parseArgs run" {
    const args = [_][]const u8{ "uwrx", "run", "--", "echo", "hello" };
    const result = try parseArgs(std.testing.allocator, &args);
    var opts = result.opts;
    defer opts.deinit();
    try std.testing.expectEqual(Command.run, result.cmd);
    try std.testing.expectEqual(@as(usize, 2), opts.command.len);
}

test {
    // Run all module tests
    _ = util;
    _ = supervisor;
    _ = manager;
    _ = tracing;
    _ = network;
    _ = filesystem;
    _ = sources;
    _ = reproducibility;
    _ = rebuild;
    _ = inspect;
    _ = bundle;
}
