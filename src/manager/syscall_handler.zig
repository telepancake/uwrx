//! Syscall handler for intercepted syscalls
//!
//! Processes seccomp notifications and handles syscalls appropriately
//! based on uwrx's requirements (filesystem overlay, network isolation, etc.)
//!
//! IMPORTANT: Manager thread and target thread share the same address space
//! (via CLONE_VM). This means we can directly access pointers from syscall
//! arguments without needing process_vm_writev.

const std = @import("std");
const linux = @import("../util/linux.zig");
const seccomp = @import("seccomp.zig");
const prng = @import("../reproducibility/prng.zig");
const time_mod = @import("../reproducibility/time.zig");

/// Syscall handler context
pub const HandlerContext = struct {
    allocator: std.mem.Allocator,
    seccomp_fd: linux.fd_t,
    /// Hierarchical PRNG for reproducible random
    prng_state: ?*prng.HierarchicalPrng = null,
    /// Deterministic time state
    time_state: ?*time_mod.DeterministicTime = null,
    /// Filesystem overlay state (opaque pointer)
    fs_state: ?*anyopaque = null,
    /// Network state (opaque pointer)
    net_state: ?*anyopaque = null,
};

/// Handle syscall notifications in a loop
pub fn handleLoop(ctx: *HandlerContext) !void {
    while (true) {
        const notif = seccomp.recvNotification(ctx.seccomp_fd) catch |err| switch (err) {
            error.RecvFailed => continue,
            else => return err,
        };

        const resp = handleSyscall(ctx, &notif);

        seccomp.sendResponse(ctx.seccomp_fd, &resp) catch |err| switch (err) {
            error.SendFailed => continue,
            else => return err,
        };
    }
}

/// Handle a single syscall notification
fn handleSyscall(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Check if notification is still valid (TOCTOU protection)
    if (!seccomp.isIdValid(ctx.seccomp_fd, notif.id)) {
        return seccomp.errorResponse(notif.id, std.os.linux.E.NOSYS);
    }

    return switch (notif.data.nr) {
        // Process syscalls
        linux.SYS.clone, linux.SYS.clone3, linux.SYS.fork, linux.SYS.vfork => handleProcessCreate(ctx, notif),
        linux.SYS.execve, linux.SYS.execveat => handleExec(ctx, notif),
        linux.SYS.exit, linux.SYS.exit_group => handleExit(ctx, notif),

        // File syscalls
        linux.SYS.open, linux.SYS.openat, linux.SYS.openat2, linux.SYS.creat => handleOpen(ctx, notif),
        linux.SYS.stat, linux.SYS.lstat, linux.SYS.fstat, linux.SYS.newfstatat, linux.SYS.statx => handleStat(ctx, notif),
        linux.SYS.access, linux.SYS.faccessat => handleAccess(ctx, notif),
        linux.SYS.unlink, linux.SYS.unlinkat, linux.SYS.rmdir => handleUnlink(ctx, notif),
        linux.SYS.rename, linux.SYS.renameat, linux.SYS.renameat2 => handleRename(ctx, notif),
        linux.SYS.mkdir, linux.SYS.mkdirat => handleMkdir(ctx, notif),
        linux.SYS.readlink, linux.SYS.readlinkat => handleReadlink(ctx, notif),
        linux.SYS.getdents64 => handleGetdents(ctx, notif),
        linux.SYS.getcwd => handleGetcwd(ctx, notif),
        linux.SYS.chdir, linux.SYS.fchdir => handleChdir(ctx, notif),
        linux.SYS.chmod, linux.SYS.fchmod, linux.SYS.fchmodat => handleChmod(ctx, notif),
        linux.SYS.chown, linux.SYS.fchown, linux.SYS.lchown, linux.SYS.fchownat => handleChown(ctx, notif),
        linux.SYS.utimensat => handleUtimensat(ctx, notif),

        // Network syscalls
        linux.SYS.socket => handleSocket(ctx, notif),
        linux.SYS.connect => handleConnect(ctx, notif),
        linux.SYS.bind => handleBind(ctx, notif),
        linux.SYS.listen => handleListen(ctx, notif),
        linux.SYS.accept, linux.SYS.accept4 => handleAccept(ctx, notif),
        linux.SYS.sendto, linux.SYS.sendmsg => handleSend(ctx, notif),
        linux.SYS.recvfrom, linux.SYS.recvmsg => handleRecv(ctx, notif),
        linux.SYS.getsockopt, linux.SYS.setsockopt => handleSockopt(ctx, notif),
        linux.SYS.getpeername, linux.SYS.getsockname => handleSockname(ctx, notif),

        // Random syscalls
        linux.SYS.getrandom => handleGetrandom(ctx, notif),

        // Time syscalls
        linux.SYS.clock_gettime => handleClockGettime(ctx, notif),
        linux.SYS.gettimeofday => handleGettimeofday(ctx, notif),
        linux.SYS.time => handleTimeSyscall(ctx, notif),

        else => seccomp.continueResponse(notif.id),
    };
}

// ============================================================================
// Process syscall handlers
// ============================================================================

fn handleProcessCreate(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // For process creation, we need to set up the new process with manager thread
    // For now, just continue and let it proceed
    return seccomp.continueResponse(notif.id);
}

fn handleExec(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // On exec, check if it's a bundled executable
    // For now, just continue
    return seccomp.continueResponse(notif.id);
}

fn handleExit(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Clean up any resources for this process
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// File syscall handlers
// ============================================================================

fn handleOpen(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Redirect through overlay filesystem
    // For now, just continue
    return seccomp.continueResponse(notif.id);
}

fn handleStat(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Squash timestamps
    return seccomp.continueResponse(notif.id);
}

fn handleAccess(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleUnlink(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Create whiteout instead of deleting
    return seccomp.continueResponse(notif.id);
}

fn handleRename(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleMkdir(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleReadlink(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleGetdents(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Filter out whiteouts
    return seccomp.continueResponse(notif.id);
}

fn handleGetcwd(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleChdir(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleChmod(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleChown(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleUtimensat(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// Network syscall handlers
// ============================================================================

fn handleSocket(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Redirect to supervisor for network handling
    return seccomp.continueResponse(notif.id);
}

fn handleConnect(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Redirect connections through MITM proxy
    return seccomp.continueResponse(notif.id);
}

fn handleBind(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleListen(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleAccept(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleSend(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleRecv(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleSockopt(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleSockname(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// Random syscall handlers
// ============================================================================

/// Handle getrandom syscall - provide reproducible random bytes
/// getrandom(buf, buflen, flags) -> ssize_t
///
/// Since we share address space with target (CLONE_VM), we can write
/// directly to the buffer pointer.
fn handleGetrandom(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const prng_state = ctx.prng_state orelse {
        // No PRNG state, let syscall proceed normally
        return seccomp.continueResponse(notif.id);
    };

    const buf_ptr = notif.data.args[0]; // Buffer pointer (same address space!)
    const buflen = notif.data.args[1]; // Buffer length
    // flags = notif.data.args[2] (ignored for reproducibility)

    if (buflen == 0 or buf_ptr == 0) {
        return seccomp.successResponse(notif.id, 0);
    }

    // Limit buffer size
    const max_buflen: usize = 256;
    const actual_len: usize = @min(@as(usize, @intCast(buflen)), max_buflen);

    // Direct access to target's buffer (same address space via CLONE_VM)
    const buf: [*]u8 = @ptrFromInt(buf_ptr);

    // Generate reproducible random bytes directly into target's buffer
    prng_state.fillBytes(notif.pid, buf[0..actual_len]);

    // Return bytes written (don't execute actual syscall)
    return seccomp.successResponse(notif.id, @intCast(actual_len));
}

// ============================================================================
// Time syscall handlers
// ============================================================================

/// Handle clock_gettime syscall - provide deterministic time
/// clock_gettime(clockid, *timespec) -> int
fn handleClockGettime(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const time_state = ctx.time_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const clockid = notif.data.args[0];
    const ts_ptr = notif.data.args[1];

    // Only intercept CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1)
    if (clockid != 0 and clockid != 1) {
        return seccomp.continueResponse(notif.id);
    }

    if (ts_ptr == 0) {
        return seccomp.errorResponse(notif.id, std.os.linux.E.FAULT);
    }

    // Direct access to target's timespec (same address space)
    const ts: *std.os.linux.timespec = @ptrFromInt(ts_ptr);
    const result = time_state.getTimespec();
    ts.* = result;

    return seccomp.successResponse(notif.id, 0);
}

/// Handle gettimeofday syscall - provide deterministic time
/// gettimeofday(*timeval, *timezone) -> int
fn handleGettimeofday(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const time_state = ctx.time_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const tv_ptr = notif.data.args[0];
    // timezone (args[1]) is usually NULL and deprecated

    if (tv_ptr == 0) {
        return seccomp.successResponse(notif.id, 0);
    }

    // Direct access to target's timeval (same address space)
    const tv: *std.os.linux.timeval = @ptrFromInt(tv_ptr);
    tv.* = time_state.getTimeval();

    return seccomp.successResponse(notif.id, 0);
}

/// Handle time syscall - provide deterministic time
/// time(*time_t) -> time_t
fn handleTimeSyscall(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const time_state = ctx.time_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const t_ptr = notif.data.args[0];
    const t = time_state.getTime();

    // If pointer is non-null, write to it (same address space)
    if (t_ptr != 0) {
        const t_dest: *i64 = @ptrFromInt(t_ptr);
        t_dest.* = t;
    }

    // Return time value
    return seccomp.successResponse(notif.id, t);
}

// ============================================================================
// Tests
// ============================================================================

test "handler context initialization" {
    const allocator = std.testing.allocator;
    const ctx = HandlerContext{
        .allocator = allocator,
        .seccomp_fd = -1,
    };
    try std.testing.expect(ctx.fs_state == null);
    try std.testing.expect(ctx.prng_state == null);
    try std.testing.expect(ctx.time_state == null);
}

test "getrandom handler with prng - null buffer" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.getrandom,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 16, 0, 0, 0, 0 }, // buf=NULL, len=16
        },
    };

    var prng_state = prng.HierarchicalPrng.init(12345);
    defer prng_state.deinit();

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .prng_state = &prng_state,
    };

    const resp = handleGetrandom(&ctx, &notif);
    // Should return 0 for null buffer
    try std.testing.expectEqual(@as(i64, 0), resp.val);
}

test "getrandom handler without prng" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.getrandom,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0x1000, 16, 0, 0, 0, 0 },
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .prng_state = null, // No PRNG
    };

    const resp = handleGetrandom(&ctx, &notif);
    // Should return CONTINUE flag when no PRNG state
    try std.testing.expectEqual(linux.SECCOMP_USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "time handler with null pointer" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.time,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0, 0, 0, 0, 0 }, // NULL pointer
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleTimeSyscall(&ctx, &notif);
    // Should return deterministic time value
    try std.testing.expectEqual(@as(i64, 1700000000), resp.val);
    try std.testing.expectEqual(@as(i32, 0), resp.@"error");
    try std.testing.expectEqual(@as(u32, 0), resp.flags); // Not CONTINUE
}

test "prng reproducibility across calls" {
    var prng_state = prng.HierarchicalPrng.init(12345);
    defer prng_state.deinit();

    var buf1: [16]u8 = undefined;
    var buf2: [16]u8 = undefined;

    prng_state.fillBytes(1, &buf1);

    // Reset with same seed
    var prng_state2 = prng.HierarchicalPrng.init(12345);
    defer prng_state2.deinit();

    prng_state2.fillBytes(1, &buf2);

    // Should be identical
    try std.testing.expectEqualSlices(u8, &buf1, &buf2);
}

test "time state determinism" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    const t1 = time_state.getTime();
    const t2 = time_state.getTime();

    // Frozen mode: times should be equal
    try std.testing.expectEqual(t1, t2);
    try std.testing.expectEqual(@as(i64, 1700000000), t1);
}
