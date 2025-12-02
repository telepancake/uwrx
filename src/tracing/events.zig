//! Trace event definitions
//!
//! Defines all event types that can be recorded in a trace.

const std = @import("std");

/// Event types
pub const EventType = enum(u8) {
    // Process events
    spawn,
    exec,
    exit,

    // File events
    file_open,
    file_read,
    file_write,
    file_close,
    file_stat,
    file_unlink,
    file_rename,

    // Network events
    connect,
    dns_lookup,
    send,
    recv,

    // Output events
    stdout,
    stderr,

    // Metadata events
    pid_mapping,
    clock_sync,
};

/// Process spawn event
pub const SpawnEvent = struct {
    parent_pid: u32,
    child_pid: u32,
    command: []const []const u8,
};

/// Process exec event
pub const ExecEvent = struct {
    pid: u32,
    executable: []const u8,
    args: []const []const u8,
};

/// Process exit event
pub const ExitEvent = struct {
    pid: u32,
    exit_code: u32,
};

/// File open event
pub const FileOpenEvent = struct {
    pid: u32,
    path: []const u8,
    flags: u32,
    result_fd: i32,
};

/// File read event
pub const FileReadEvent = struct {
    pid: u32,
    fd: i32,
    bytes: usize,
};

/// File write event
pub const FileWriteEvent = struct {
    pid: u32,
    fd: i32,
    bytes: usize,
};

/// File close event
pub const FileCloseEvent = struct {
    pid: u32,
    fd: i32,
};

/// File stat event
pub const FileStatEvent = struct {
    pid: u32,
    path: []const u8,
    result: i32,
};

/// File unlink event
pub const FileUnlinkEvent = struct {
    pid: u32,
    path: []const u8,
    result: i32,
};

/// File rename event
pub const FileRenameEvent = struct {
    pid: u32,
    old_path: []const u8,
    new_path: []const u8,
    result: i32,
};

/// Network connect event
pub const ConnectEvent = struct {
    pid: u32,
    domain: []const u8,
    port: u16,
};

/// DNS lookup event
pub const DnsLookupEvent = struct {
    pid: u32,
    domain: []const u8,
    result_ip: []const u8,
};

/// Network send event
pub const SendEvent = struct {
    pid: u32,
    fd: i32,
    bytes: usize,
};

/// Network recv event
pub const RecvEvent = struct {
    pid: u32,
    fd: i32,
    bytes: usize,
};

/// Standard output event
pub const StdoutEvent = struct {
    pid: u32,
    data: []const u8,
};

/// Standard error event
pub const StderrEvent = struct {
    pid: u32,
    data: []const u8,
};

/// PID mapping event
pub const PidMappingEvent = struct {
    host_pid: i32,
    uwrx_pid: u32,
    versioned_pid: ?[]const u8,
};

/// Clock sync event
pub const ClockSyncEvent = struct {
    monotonic_ns: i64,
    wall_clock_ns: i64,
};

/// Union of all event types
pub const Event = union(EventType) {
    spawn: SpawnEvent,
    exec: ExecEvent,
    exit: ExitEvent,
    file_open: FileOpenEvent,
    file_read: FileReadEvent,
    file_write: FileWriteEvent,
    file_close: FileCloseEvent,
    file_stat: FileStatEvent,
    file_unlink: FileUnlinkEvent,
    file_rename: FileRenameEvent,
    connect: ConnectEvent,
    dns_lookup: DnsLookupEvent,
    send: SendEvent,
    recv: RecvEvent,
    stdout: StdoutEvent,
    stderr: StderrEvent,
    pid_mapping: PidMappingEvent,
    clock_sync: ClockSyncEvent,
};

/// Event header for serialization
pub const EventHeader = extern struct {
    event_type: EventType,
    timestamp_delta: i64, // Delta from trace start in nanoseconds
    length: u32, // Length of event data
};

test "event size" {
    try std.testing.expect(@sizeOf(EventHeader) > 0);
}
