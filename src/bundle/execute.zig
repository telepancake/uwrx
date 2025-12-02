//! Direct execution of bundled code
//!
//! When manager thread intercepts execve() for a bundled executable,
//! this module handles direct execution without filesystem I/O.

const std = @import("std");
const mod = @import("mod.zig");

/// Execute a bundled executable
pub fn executeBundled(bundled: mod.BundledExec, args: []const []const u8, env: []const []const u8) !noreturn {
    _ = env;
    _ = args;

    // The bundled code is already loaded in memory as part of uwrx
    // We just need to:
    // 1. Set up the execution environment (stack, auxv)
    // 2. Transfer control to the entry point

    // Get pointer to bundled code
    // In a real implementation, this would be the actual mapped address
    const code_ptr = getBundledCodeAddress(bundled);

    // Set up stack and transfer control
    transferControl(code_ptr, bundled.entry_offset);
}

/// Get the address where bundled code is loaded
fn getBundledCodeAddress(bundled: mod.BundledExec) [*]const u8 {
    // The bundled code is part of the uwrx binary, which is mapped
    // at a known high address after self-relocation

    // Read from /proc/self/exe at the bundled offset
    // In a real implementation, we'd use the already-mapped memory
    _ = bundled;

    // Placeholder - would return actual mapped address
    return @ptrFromInt(0x7f0000000000);
}

/// Transfer control to bundled code
fn transferControl(code_ptr: [*]const u8, entry_offset: usize) noreturn {
    // Calculate entry point address
    const entry: *const fn () callconv(.C) noreturn = @ptrCast(code_ptr + entry_offset);

    // In a real implementation, we would:
    // 1. Set up proper stack frame
    // 2. Set up auxv with AT_ENTRY, AT_PHDR, etc.
    // 3. Clear registers
    // 4. Jump to entry

    // For now, just call the entry point
    entry();
}

/// Set up execution environment for bundled code
pub const ExecEnv = struct {
    /// Stack pointer
    stack: [*]u8,
    /// Stack size
    stack_size: usize,
    /// Argument count
    argc: usize,
    /// Argument array
    argv: [*]const [*:0]const u8,
    /// Environment array
    envp: [*]const [*:0]const u8,
    /// Auxiliary vector
    auxv: [*]const AuxEntry,
};

/// Auxiliary vector entry
pub const AuxEntry = struct {
    type: AuxType,
    value: usize,
};

/// Auxiliary vector types
pub const AuxType = enum(usize) {
    AT_NULL = 0,
    AT_IGNORE = 1,
    AT_EXECFD = 2,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_FLAGS = 8,
    AT_ENTRY = 9,
    AT_NOTELF = 10,
    AT_UID = 11,
    AT_EUID = 12,
    AT_GID = 13,
    AT_EGID = 14,
    AT_CLKTCK = 17,
    AT_PLATFORM = 15,
    AT_HWCAP = 16,
    AT_SECURE = 23,
    AT_RANDOM = 25,
    AT_EXECFN = 31,
    _,
};

test "AuxType values" {
    try std.testing.expectEqual(@as(usize, 0), @intFromEnum(AuxType.AT_NULL));
    try std.testing.expectEqual(@as(usize, 25), @intFromEnum(AuxType.AT_RANDOM));
}
