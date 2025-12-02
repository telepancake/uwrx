//! Terminal UI for trace inspection
//!
//! Interactive terminal-based UI for exploring traces.

const std = @import("std");

/// Terminal escape codes
const Ansi = struct {
    const clear_screen = "\x1b[2J";
    const cursor_home = "\x1b[H";
    const cursor_hide = "\x1b[?25l";
    const cursor_show = "\x1b[?25h";
    const bold = "\x1b[1m";
    const reset = "\x1b[0m";
    const reverse = "\x1b[7m";
    const clear_line = "\x1b[2K";

    fn moveTo(row: u32, col: u32) [16]u8 {
        var buf: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "\x1b[{d};{d}H", .{ row, col }) catch {};
        return buf;
    }
};

/// TUI state
pub const TuiState = struct {
    allocator: std.mem.Allocator,
    /// Trace path
    trace_path: ?[]const u8,
    /// Process list
    processes: std.ArrayList(ProcessEntry),
    /// Selected index
    selected: usize,
    /// Scroll offset
    scroll: usize,
    /// Terminal size
    rows: u32,
    cols: u32,
    /// Current view
    view: View,

    const View = enum {
        process_list,
        process_detail,
        file_list,
        event_list,
    };

    pub fn init(allocator: std.mem.Allocator) TuiState {
        return .{
            .allocator = allocator,
            .trace_path = null,
            .processes = std.ArrayList(ProcessEntry).init(allocator),
            .selected = 0,
            .scroll = 0,
            .rows = 24,
            .cols = 80,
            .view = .process_list,
        };
    }

    pub fn deinit(self: *TuiState) void {
        self.processes.deinit();
    }

    /// Load trace data
    pub fn loadTrace(self: *TuiState, path: []const u8) !void {
        self.trace_path = path;
        // Parse trace and populate processes
        // For now, add placeholder
        try self.processes.append(.{
            .pid = 2,
            .parent_pid = 1,
            .command = "test",
            .exit_status = 0,
        });
    }

    /// Render the UI
    pub fn render(self: *TuiState, writer: anytype) !void {
        // Clear and home
        try writer.writeAll(Ansi.clear_screen);
        try writer.writeAll(Ansi.cursor_home);

        // Header
        try writer.writeAll(Ansi.bold);
        try writer.writeAll("uwrx - Trace Inspector");
        try writer.writeAll(Ansi.reset);
        try writer.writeAll("\n");

        if (self.trace_path) |path| {
            try writer.print("Trace: {s}\n", .{path});
        }
        try writer.writeAll("\n");

        // Content based on view
        switch (self.view) {
            .process_list => try self.renderProcessList(writer),
            .process_detail => try self.renderProcessDetail(writer),
            .file_list => try self.renderFileList(writer),
            .event_list => try self.renderEventList(writer),
        }

        // Footer
        try writer.writeAll("\n");
        try writer.writeAll("q:quit  j/k:up/down  enter:select  b:back");
    }

    fn renderProcessList(self: *TuiState, writer: anytype) !void {
        try writer.writeAll("Processes:\n\n");

        for (self.processes.items, 0..) |proc, i| {
            if (i == self.selected) {
                try writer.writeAll(Ansi.reverse);
            }

            try writer.print("  {d}: {s} (exit {d})\n", .{ proc.pid, proc.command, proc.exit_status });

            if (i == self.selected) {
                try writer.writeAll(Ansi.reset);
            }
        }
    }

    fn renderProcessDetail(self: *TuiState, writer: anytype) !void {
        if (self.selected >= self.processes.items.len) return;

        const proc = self.processes.items[self.selected];
        try writer.print("Process {d}\n\n", .{proc.pid});
        try writer.print("Command: {s}\n", .{proc.command});
        try writer.print("Parent:  {d}\n", .{proc.parent_pid});
        try writer.print("Exit:    {d}\n", .{proc.exit_status});
    }

    fn renderFileList(self: *TuiState, writer: anytype) !void {
        try writer.writeAll("Files:\n\n");
        try writer.writeAll("  (not implemented)\n");
    }

    fn renderEventList(self: *TuiState, writer: anytype) !void {
        try writer.writeAll("Events:\n\n");
        try writer.writeAll("  (not implemented)\n");
    }

    /// Handle input
    pub fn handleInput(self: *TuiState, key: u8) bool {
        switch (key) {
            'q' => return false,
            'j' => {
                if (self.selected + 1 < self.processes.items.len) {
                    self.selected += 1;
                }
            },
            'k' => {
                if (self.selected > 0) {
                    self.selected -= 1;
                }
            },
            '\r', '\n' => {
                if (self.view == .process_list) {
                    self.view = .process_detail;
                }
            },
            'b' => {
                self.view = .process_list;
            },
            else => {},
        }
        return true;
    }
};

/// Process entry
pub const ProcessEntry = struct {
    pid: u32,
    parent_pid: u32,
    command: []const u8,
    exit_status: u32,
};

/// Run the TUI
pub fn run(allocator: std.mem.Allocator) !void {
    var state = TuiState.init(allocator);
    defer state.deinit();

    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();
    const writer = stdout.writer();

    // Set raw mode
    var original_termios = try std.posix.tcgetattr(stdin.handle);
    var raw = original_termios;
    raw.lflag.ECHO = false;
    raw.lflag.ICANON = false;
    try std.posix.tcsetattr(stdin.handle, .NOW, raw);
    defer std.posix.tcsetattr(stdin.handle, .NOW, original_termios) catch {};

    // Hide cursor
    try writer.writeAll(Ansi.cursor_hide);
    defer writer.writeAll(Ansi.cursor_show) catch {};

    // Main loop
    while (true) {
        try state.render(writer);

        var buf: [1]u8 = undefined;
        const n = try stdin.read(&buf);
        if (n == 0) break;

        if (!state.handleInput(buf[0])) break;
    }

    // Clear screen on exit
    try writer.writeAll(Ansi.clear_screen);
    try writer.writeAll(Ansi.cursor_home);
}

test "TuiState initialization" {
    const allocator = std.testing.allocator;
    var state = TuiState.init(allocator);
    defer state.deinit();

    try std.testing.expectEqual(@as(usize, 0), state.selected);
}
