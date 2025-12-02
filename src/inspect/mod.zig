//! Inspection module
//!
//! Provides CLI and TUI tools for examining traces.

const std = @import("std");
const main = @import("../main.zig");

pub const cli = @import("cli.zig");
pub const tui = @import("tui.zig");

/// Run CLI inspection
pub fn runCli(allocator: std.mem.Allocator, args: []const []const u8) !void {
    try cli.run(allocator, args);
}

/// Run TUI inspection
pub fn runTui(allocator: std.mem.Allocator, options: *const main.Options) !void {
    _ = options;
    try tui.run(allocator);
}

test {
    _ = cli;
    _ = tui;
}
