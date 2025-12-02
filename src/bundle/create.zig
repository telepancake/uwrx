//! Bundle creation tool
//!
//! Creates bundled uwrx binaries containing executables and data overlays.

const std = @import("std");
const format = @import("format.zig");
const elf = @import("../manager/elf.zig");

/// Bundle creation options
pub const CreateOptions = struct {
    output: []const u8,
    executables: []const ExecutableSpec,
    data_overlays: []const DataSpec,
};

/// Executable to bundle
pub const ExecutableSpec = struct {
    name: []const u8,
    path: []const u8,
};

/// Data overlay to bundle
pub const DataSpec = struct {
    name: []const u8,
    path: []const u8,
};

/// Run the bundle creation command
pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var output: ?[]const u8 = null;
    var executables = std.ArrayList(ExecutableSpec).init(allocator);
    defer executables.deinit();
    var data_overlays = std.ArrayList(DataSpec).init(allocator);
    defer data_overlays.deinit();

    // Parse arguments
    var i: usize = 2; // Skip "uwrx" and "bundle"
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--output") or std.mem.eql(u8, args[i], "-o")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --output requires argument\n", .{});
                return;
            }
            output = args[i];
        } else if (std.mem.eql(u8, args[i], "--add")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --add requires argument\n", .{});
                return;
            }
            const spec = parseExecutableSpec(args[i]) orelse {
                std.debug.print("Error: Invalid executable spec: {s}\n", .{args[i]});
                return;
            };
            try executables.append(spec);
        } else if (std.mem.eql(u8, args[i], "--data")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --data requires argument\n", .{});
                return;
            }
            const spec = parseDataSpec(args[i]) orelse {
                std.debug.print("Error: Invalid data spec: {s}\n", .{args[i]});
                return;
            };
            try data_overlays.append(spec);
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            printHelp();
            return;
        }
    }

    if (output == null) {
        std.debug.print("Error: --output is required\n", .{});
        printHelp();
        return;
    }

    // Create the bundle
    try createBundle(allocator, .{
        .output = output.?,
        .executables = executables.items,
        .data_overlays = data_overlays.items,
    });

    std.debug.print("Bundle created: {s}\n", .{output.?});
}

fn printHelp() void {
    const help =
        \\uwrx bundle - Create bundled uwrx with executables
        \\
        \\USAGE:
        \\    uwrx bundle --output <path> [options]
        \\
        \\OPTIONS:
        \\    -o, --output <path>     Output path for bundled uwrx (required)
        \\    --add <name>=<path>     Add executable to bundle (repeatable)
        \\    --data <name>=<path>    Add data overlay (repeatable)
        \\    -h, --help              Show this help
        \\
        \\EXAMPLES:
        \\    uwrx bundle -o uwrx-gcc --add gcc=/usr/bin/gcc
        \\    uwrx bundle -o uwrx-toolchain --add gcc=/usr/bin/gcc --add ld=/usr/bin/ld
        \\
        \\REQUIREMENTS:
        \\    Bundled executables must be:
        \\    - Statically linked
        \\    - Position-independent (relocatable)
        \\
    ;
    std.debug.print("{s}", .{help});
}

fn parseExecutableSpec(spec: []const u8) ?ExecutableSpec {
    const eq = std.mem.indexOf(u8, spec, "=") orelse return null;
    return .{
        .name = spec[0..eq],
        .path = spec[eq + 1 ..],
    };
}

fn parseDataSpec(spec: []const u8) ?DataSpec {
    const eq = std.mem.indexOf(u8, spec, "=") orelse return null;
    return .{
        .name = spec[0..eq],
        .path = spec[eq + 1 ..],
    };
}

/// Create a bundled uwrx binary
fn createBundle(allocator: std.mem.Allocator, options: CreateOptions) !void {
    // Copy own executable as base
    const self_path = "/proc/self/exe";

    // Read self
    const self_content = try std.fs.cwd().readFileAlloc(allocator, self_path, 100 * 1024 * 1024);
    defer allocator.free(self_content);

    // Create output file
    const output_file = try std.fs.createFileAbsolute(options.output, .{});
    defer output_file.close();

    // Write base
    try output_file.writeAll(self_content);

    // For each executable, add as new section
    for (options.executables) |exec| {
        try addExecutableSection(allocator, output_file, exec);
    }

    // For each data overlay, add as new section
    for (options.data_overlays) |data_spec| {
        try addDataSection(allocator, output_file, data_spec);
    }

    // Make executable
    try std.posix.fchmod(output_file.handle, 0o755);
}

fn addExecutableSection(allocator: std.mem.Allocator, output_file: std.fs.File, spec: ExecutableSpec) !void {
    _ = allocator;

    // Read executable
    const exe_content = try std.fs.cwd().readFileAlloc(std.heap.page_allocator, spec.path, 100 * 1024 * 1024);
    defer std.heap.page_allocator.free(exe_content);

    // Verify it's static and PIE
    if (!isValidBundleCandidate(exe_content)) {
        std.debug.print("Warning: {s} may not be suitable for bundling (not static/PIE)\n", .{spec.name});
    }

    // Create header
    var header = format.BundleHeader{
        .magic = format.BUNDLE_MAGIC,
        .version = format.BUNDLE_VERSION,
        .entry_offset = 0, // Would extract from ELF
        .flags = 0,
        .reserved = [_]u8{0} ** 12,
    };

    // Get entry point from ELF
    const ehdr: *const elf.Elf64_Ehdr = @ptrCast(exe_content.ptr);
    header.entry_offset = @truncate(ehdr.e_entry);

    // Seek to end
    try output_file.seekFromEnd(0);

    // Write header and content
    try output_file.writeAll(std.mem.asBytes(&header));
    try output_file.writeAll(exe_content);

    // TODO: Update ELF section headers to add new section
    // This is complex and would require full ELF manipulation
}

fn addDataSection(_: std.mem.Allocator, _: std.fs.File, _: DataSpec) !void {
    // TODO: Read data, compress as squashfs, append as section
}

fn isValidBundleCandidate(content: []const u8) bool {
    if (content.len < @sizeOf(elf.Elf64_Ehdr)) return false;

    const ehdr: *const elf.Elf64_Ehdr = @ptrCast(content.ptr);

    // Check ELF magic
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], &elf.ELF_MAGIC)) return false;

    // Check if PIE (ET_DYN with no INTERP is a static PIE)
    // This is a simplified check
    return ehdr.e_type == elf.ET_DYN or ehdr.e_type == elf.ET_EXEC;
}

test "parseExecutableSpec" {
    const spec = parseExecutableSpec("gcc=/usr/bin/gcc");
    try std.testing.expect(spec != null);
    try std.testing.expectEqualStrings("gcc", spec.?.name);
    try std.testing.expectEqualStrings("/usr/bin/gcc", spec.?.path);
}
