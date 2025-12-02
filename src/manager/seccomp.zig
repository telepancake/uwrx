//! Seccomp filter setup for syscall interception
//!
//! Creates BPF filters that redirect syscalls to USER_NOTIF
//! for handling by the manager thread.

const std = @import("std");
const linux = @import("../util/linux.zig");

/// Syscalls to intercept with USER_NOTIF
const intercepted_syscalls = [_]i32{
    // Process
    linux.SYS.clone,
    linux.SYS.clone3,
    linux.SYS.fork,
    linux.SYS.vfork,
    linux.SYS.execve,
    linux.SYS.execveat,
    linux.SYS.exit,
    linux.SYS.exit_group,

    // File operations
    linux.SYS.open,
    linux.SYS.openat,
    linux.SYS.openat2,
    linux.SYS.creat,
    linux.SYS.unlink,
    linux.SYS.unlinkat,
    linux.SYS.rename,
    linux.SYS.renameat,
    linux.SYS.renameat2,
    linux.SYS.mkdir,
    linux.SYS.mkdirat,
    linux.SYS.rmdir,
    linux.SYS.stat,
    linux.SYS.fstat,
    linux.SYS.lstat,
    linux.SYS.newfstatat,
    linux.SYS.access,
    linux.SYS.faccessat,
    linux.SYS.readlink,
    linux.SYS.readlinkat,
    linux.SYS.chmod,
    linux.SYS.fchmod,
    linux.SYS.fchmodat,
    linux.SYS.chown,
    linux.SYS.fchown,
    linux.SYS.lchown,
    linux.SYS.fchownat,
    linux.SYS.utimensat,
    linux.SYS.getdents64,
    linux.SYS.getcwd,
    linux.SYS.chdir,
    linux.SYS.fchdir,
    linux.SYS.statx,

    // Network
    linux.SYS.socket,
    linux.SYS.connect,
    linux.SYS.bind,
    linux.SYS.listen,
    linux.SYS.accept,
    linux.SYS.accept4,
    linux.SYS.sendto,
    linux.SYS.recvfrom,
    linux.SYS.sendmsg,
    linux.SYS.recvmsg,
    linux.SYS.getsockopt,
    linux.SYS.setsockopt,
    linux.SYS.getpeername,
    linux.SYS.getsockname,

    // Random
    linux.SYS.getrandom,

    // Time
    linux.SYS.clock_gettime,
    linux.SYS.gettimeofday,
    linux.SYS.time,
};

/// Maximum number of BPF instructions
const MAX_BPF_INSNS = 256;

/// Build the seccomp BPF filter
fn buildFilter() struct { filter: [MAX_BPF_INSNS]linux.SockFilter, count: usize } {
    var filter: [MAX_BPF_INSNS]linux.SockFilter = @splat(linux.SockFilter{ .code = 0, .jt = 0, .jf = 0, .k = 0 });
    var idx: usize = 0;

    // Load architecture
    filter[idx] = linux.bpfStmt(
        linux.BPF_LD | linux.BPF_W | linux.BPF_ABS,
        @offsetOf(linux.SeccompData, "arch"),
    );
    idx += 1;

    // Check architecture
    filter[idx] = linux.bpfJump(
        linux.BPF_JMP | linux.BPF_JEQ | linux.BPF_K,
        linux.auditArch(),
        1,
        0,
    );
    idx += 1;

    // Kill on wrong architecture
    filter[idx] = linux.bpfStmt(linux.BPF_RET | linux.BPF_K, linux.SECCOMP_RET_KILL_PROCESS);
    idx += 1;

    // Load syscall number
    filter[idx] = linux.bpfStmt(
        linux.BPF_LD | linux.BPF_W | linux.BPF_ABS,
        @offsetOf(linux.SeccompData, "nr"),
    );
    idx += 1;

    // Check each intercepted syscall
    for (intercepted_syscalls) |syscall| {
        // Jump to USER_NOTIF return if match
        const remaining = intercepted_syscalls.len - @as(usize, @intCast(std.mem.indexOf(i32, &intercepted_syscalls, &[_]i32{syscall}).?));
        filter[idx] = linux.bpfJump(
            linux.BPF_JMP | linux.BPF_JEQ | linux.BPF_K,
            @intCast(syscall),
            @intCast(remaining), // Jump to USER_NOTIF
            0, // Continue checking
        );
        idx += 1;
    }

    // Default: allow
    filter[idx] = linux.bpfStmt(linux.BPF_RET | linux.BPF_K, linux.SECCOMP_RET_ALLOW);
    idx += 1;

    // USER_NOTIF for intercepted syscalls
    filter[idx] = linux.bpfStmt(linux.BPF_RET | linux.BPF_K, linux.SECCOMP_RET_USER_NOTIF);
    idx += 1;

    return .{ .filter = filter, .count = idx };
}

/// Set up seccomp filter and return the notification fd
pub fn setupFilter() !linux.fd_t {
    const result_filter = buildFilter();

    const prog = linux.SockFprog{
        .len = @intCast(result_filter.count),
        .filter = &result_filter.filter,
    };

    // Set no_new_privs (required for seccomp without CAP_SYS_ADMIN)
    const prctl_result = linux.prctl(linux.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (prctl_result != 0) {
        return error.PrctlFailed;
    }

    // Install filter with NEW_LISTENER flag
    const result = linux.seccomp(
        linux.SECCOMP_SET_MODE_FILTER,
        linux.SECCOMP_FILTER_FLAG_NEW_LISTENER,
        @ptrCast(@constCast(&prog)),
    );

    if (result < 0) {
        return error.SeccompFailed;
    }

    return @intCast(result);
}

/// Receive a seccomp notification
pub fn recvNotification(fd: linux.fd_t) !linux.SeccompNotif {
    var notif: linux.SeccompNotif = undefined;

    const result = linux.ioctl(fd, linux.SECCOMP_IOCTL_NOTIF_RECV, @intFromPtr(&notif));
    if (result < 0) {
        return error.RecvFailed;
    }

    return notif;
}

/// Send a seccomp notification response
pub fn sendResponse(fd: linux.fd_t, resp: *const linux.SeccompNotifResp) !void {
    const result = linux.ioctl(fd, linux.SECCOMP_IOCTL_NOTIF_SEND, @intFromPtr(resp));
    if (result < 0) {
        return error.SendFailed;
    }
}

/// Check if a notification ID is still valid
pub fn isIdValid(fd: linux.fd_t, id: u64) bool {
    var check_id = id;
    const result = linux.ioctl(fd, linux.SECCOMP_IOCTL_NOTIF_ID_VALID, @intFromPtr(&check_id));
    return result == 0;
}

/// Create a continue response (let syscall proceed normally)
pub fn continueResponse(id: u64) linux.SeccompNotifResp {
    return .{
        .id = id,
        .val = 0,
        .@"error" = 0,
        .flags = linux.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
}

/// Create an error response
pub fn errorResponse(id: u64, errno: i32) linux.SeccompNotifResp {
    return .{
        .id = id,
        .val = 0,
        .@"error" = -errno,
        .flags = 0,
    };
}

/// Create a success response with return value
pub fn successResponse(id: u64, val: i64) linux.SeccompNotifResp {
    return .{
        .id = id,
        .val = val,
        .@"error" = 0,
        .flags = 0,
    };
}

test "filter size" {
    const result = buildFilter();
    // Should have reasonable number of instructions
    try std.testing.expect(result.count > 0);
    try std.testing.expect(result.count < MAX_BPF_INSNS);
}
