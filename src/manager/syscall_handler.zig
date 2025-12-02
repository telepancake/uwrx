//! Syscall handler for intercepted syscalls
//!
//! Processes seccomp notifications and handles syscalls appropriately
//! based on uwrx's requirements (filesystem overlay, network isolation, etc.)

const std = @import("std");
const linux = @import("../util/linux.zig");
const seccomp = @import("seccomp.zig");

/// Syscall handler context
pub const HandlerContext = struct {
    allocator: std.mem.Allocator,
    seccomp_fd: linux.fd_t,
    /// Filesystem overlay state
    fs_state: ?*anyopaque = null,
    /// Network state
    net_state: ?*anyopaque = null,
    /// PRNG state for reproducible random
    prng_state: ?*anyopaque = null,
    /// Time state for deterministic time
    time_state: ?*anyopaque = null,
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
        linux.SYS.clock_gettime, linux.SYS.gettimeofday, linux.SYS.time => handleTime(ctx, notif),

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

fn handleGetrandom(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Return PRNG-generated random bytes
    // For now, just continue
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// Time syscall handlers
// ============================================================================

fn handleTime(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Return deterministic time
    // For now, just continue
    return seccomp.continueResponse(notif.id);
}

test "handler context initialization" {
    const allocator = std.testing.allocator;
    var ctx = HandlerContext{
        .allocator = allocator,
        .seccomp_fd = -1,
    };
    try std.testing.expect(ctx.fs_state == null);
}
