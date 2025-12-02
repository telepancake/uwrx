//! Linux-specific syscall wrappers not available in std
//! Provides low-level access to Linux kernel features needed for uwrx

const std = @import("std");
const os = std.os;
const linux = std.os.linux;
const fd_t = linux.fd_t;

// ============================================================================
// prctl constants and wrapper
// ============================================================================

pub const PR_SET_CHILD_SUBREAPER = 36;
pub const PR_GET_CHILD_SUBREAPER = 37;
pub const PR_SET_NO_NEW_PRIVS = 38;
pub const PR_SET_SECCOMP = 22;

pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return linux.syscall5(.prctl, @intCast(option), arg2, arg3, arg4, arg5);
}

pub fn setChildSubreaper(enable: bool) !void {
    const result = prctl(PR_SET_CHILD_SUBREAPER, @intFromBool(enable), 0, 0, 0);
    if (result != 0) {
        return error.PrctlFailed;
    }
}

// ============================================================================
// seccomp structures and constants
// ============================================================================

pub const SECCOMP_SET_MODE_STRICT = 0;
pub const SECCOMP_SET_MODE_FILTER = 1;
pub const SECCOMP_GET_ACTION_AVAIL = 2;
pub const SECCOMP_GET_NOTIF_SIZES = 3;

pub const SECCOMP_FILTER_FLAG_TSYNC = 1 << 0;
pub const SECCOMP_FILTER_FLAG_LOG = 1 << 1;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW = 1 << 2;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3;
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH = 1 << 4;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV = 1 << 5;

pub const SECCOMP_RET_KILL_PROCESS = 0x80000000;
pub const SECCOMP_RET_KILL_THREAD = 0x00000000;
pub const SECCOMP_RET_TRAP = 0x00030000;
pub const SECCOMP_RET_ERRNO = 0x00050000;
pub const SECCOMP_RET_USER_NOTIF = 0x7fc00000;
pub const SECCOMP_RET_TRACE = 0x7ff00000;
pub const SECCOMP_RET_LOG = 0x7ffc0000;
pub const SECCOMP_RET_ALLOW = 0x7fff0000;

pub const SECCOMP_RET_ACTION_FULL = 0xffff0000;
pub const SECCOMP_RET_DATA = 0x0000ffff;

// seccomp ioctl commands
pub const SECCOMP_IOCTL_NOTIF_RECV = 0xc0502100;
pub const SECCOMP_IOCTL_NOTIF_SEND = 0xc0182101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD = 0x40182103;

// seccomp notification flags
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1 << 0;

// seccomp_data structure (matches BPF packet data)
pub const SeccompData = extern struct {
    nr: i32, // syscall number
    arch: u32, // AUDIT_ARCH_*
    instruction_pointer: u64,
    args: [6]u64,
};

// seccomp notification structure
pub const SeccompNotif = extern struct {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
};

// seccomp notification response
pub const SeccompNotifResp = extern struct {
    id: u64,
    val: i64,
    @"error": i32,
    flags: u32,
};

// seccomp notification sizes (for version compatibility)
pub const SeccompNotifSizes = extern struct {
    seccomp_notif: u16,
    seccomp_notif_resp: u16,
    seccomp_data: u16,
};

// seccomp addfd structure
pub const SeccompNotifAddfd = extern struct {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
};

pub fn seccomp(operation: u32, flags: u32, args: ?*anyopaque) isize {
    const result = linux.syscall3(
        .seccomp,
        operation,
        flags,
        @intFromPtr(args),
    );
    return @bitCast(result);
}

pub fn getNotifSizes() !SeccompNotifSizes {
    var sizes: SeccompNotifSizes = undefined;
    const result = seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
    if (result < 0) {
        return error.SeccompFailed;
    }
    return sizes;
}

// ============================================================================
// BPF structures for seccomp filter
// ============================================================================

pub const BPF_LD = 0x00;
pub const BPF_LDX = 0x01;
pub const BPF_ST = 0x02;
pub const BPF_STX = 0x03;
pub const BPF_ALU = 0x04;
pub const BPF_JMP = 0x05;
pub const BPF_RET = 0x06;
pub const BPF_MISC = 0x07;

pub const BPF_W = 0x00; // word (4 bytes)
pub const BPF_H = 0x08; // half-word (2 bytes)
pub const BPF_B = 0x10; // byte

pub const BPF_IMM = 0x00;
pub const BPF_ABS = 0x20;
pub const BPF_IND = 0x40;
pub const BPF_MEM = 0x60;
pub const BPF_LEN = 0x80;
pub const BPF_MSH = 0xa0;

pub const BPF_ADD = 0x00;
pub const BPF_SUB = 0x10;
pub const BPF_MUL = 0x20;
pub const BPF_DIV = 0x30;
pub const BPF_OR = 0x40;
pub const BPF_AND = 0x50;
pub const BPF_LSH = 0x60;
pub const BPF_RSH = 0x70;
pub const BPF_NEG = 0x80;
pub const BPF_MOD = 0x90;
pub const BPF_XOR = 0xa0;

pub const BPF_JA = 0x00;
pub const BPF_JEQ = 0x10;
pub const BPF_JGT = 0x20;
pub const BPF_JGE = 0x30;
pub const BPF_JSET = 0x40;

pub const BPF_K = 0x00;
pub const BPF_X = 0x08;

pub const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

pub const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

// BPF instruction helpers
pub fn bpfStmt(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

pub fn bpfJump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

// ============================================================================
// clone3 structures and wrapper
// ============================================================================

pub const CLONE_VM = 0x00000100;
pub const CLONE_FS = 0x00000200;
pub const CLONE_FILES = 0x00000400;
pub const CLONE_SIGHAND = 0x00000800;
pub const CLONE_PIDFD = 0x00001000;
pub const CLONE_PTRACE = 0x00002000;
pub const CLONE_VFORK = 0x00004000;
pub const CLONE_PARENT = 0x00008000;
pub const CLONE_THREAD = 0x00010000;
pub const CLONE_NEWNS = 0x00020000;
pub const CLONE_SYSVSEM = 0x00040000;
pub const CLONE_SETTLS = 0x00080000;
pub const CLONE_PARENT_SETTID = 0x00100000;
pub const CLONE_CHILD_CLEARTID = 0x00200000;
pub const CLONE_DETACHED = 0x00400000;
pub const CLONE_UNTRACED = 0x00800000;
pub const CLONE_CHILD_SETTID = 0x01000000;
pub const CLONE_NEWCGROUP = 0x02000000;
pub const CLONE_NEWUTS = 0x04000000;
pub const CLONE_NEWIPC = 0x08000000;
pub const CLONE_NEWUSER = 0x10000000;
pub const CLONE_NEWPID = 0x20000000;
pub const CLONE_NEWNET = 0x40000000;
pub const CLONE_IO = 0x80000000;

pub const CLONE_CLEAR_SIGHAND = 0x100000000;
pub const CLONE_INTO_CGROUP = 0x200000000;
pub const CLONE_NEWTIME = 0x00000080;

pub const CloneArgs = extern struct {
    flags: u64 = 0,
    pidfd: u64 = 0,
    child_tid: u64 = 0,
    parent_tid: u64 = 0,
    exit_signal: u64 = 0,
    stack: u64 = 0,
    stack_size: u64 = 0,
    tls: u64 = 0,
    set_tid: u64 = 0,
    set_tid_size: u64 = 0,
    cgroup: u64 = 0,
};

pub fn clone3(args: *const CloneArgs) isize {
    const result = linux.syscall2(
        .clone3,
        @intFromPtr(args),
        @sizeOf(CloneArgs),
    );
    return @bitCast(result);
}

// ============================================================================
// pidfd syscalls
// ============================================================================

pub const PIDFD_NONBLOCK = linux.O.NONBLOCK;

pub fn pidfdOpen(pid: linux.pid_t, flags: u32) !fd_t {
    const result = linux.syscall2(.pidfd_open, @intCast(pid), flags);
    const signed: isize = @bitCast(result);
    if (signed < 0) {
        return error.PidfdOpenFailed;
    }
    return @intCast(result);
}

pub fn pidfdGetfd(pidfd: fd_t, targetfd: fd_t, flags: u32) !fd_t {
    const result = linux.syscall3(.pidfd_getfd, @intCast(pidfd), @intCast(targetfd), flags);
    const signed: isize = @bitCast(result);
    if (signed < 0) {
        return error.PidfdGetfdFailed;
    }
    return @intCast(result);
}

// ============================================================================
// memfd_create
// ============================================================================

pub const MFD_CLOEXEC = 0x0001;
pub const MFD_ALLOW_SEALING = 0x0002;
pub const MFD_HUGETLB = 0x0004;

pub fn memfdCreate(name: [*:0]const u8, flags: u32) !fd_t {
    const result = linux.syscall2(.memfd_create, @intFromPtr(name), flags);
    const signed: isize = @bitCast(result);
    if (signed < 0) {
        return error.MemfdCreateFailed;
    }
    return @intCast(result);
}

// ============================================================================
// fallocate
// ============================================================================

pub const FALLOC_FL_KEEP_SIZE = 0x01;
pub const FALLOC_FL_PUNCH_HOLE = 0x02;
pub const FALLOC_FL_NO_HIDE_STALE = 0x04;
pub const FALLOC_FL_COLLAPSE_RANGE = 0x08;
pub const FALLOC_FL_ZERO_RANGE = 0x10;
pub const FALLOC_FL_INSERT_RANGE = 0x20;
pub const FALLOC_FL_UNSHARE_RANGE = 0x40;

pub fn fallocate(fd: fd_t, mode: i32, offset: i64, len: i64) !void {
    const result = linux.syscall4(
        .fallocate,
        @intCast(fd),
        @bitCast(@as(isize, mode)),
        @bitCast(offset),
        @bitCast(len),
    );
    const signed: isize = @bitCast(result);
    if (signed < 0) {
        return error.FallocateFailed;
    }
}

pub fn punchHole(fd: fd_t, offset: i64, len: i64) !void {
    try fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, len);
}

// ============================================================================
// Architecture detection for seccomp
// ============================================================================

pub const AUDIT_ARCH_X86_64 = 0xc000003e;
pub const AUDIT_ARCH_AARCH64 = 0xc00000b7;
pub const AUDIT_ARCH_I386 = 0x40000003;
pub const AUDIT_ARCH_ARM = 0x40000028;

pub fn auditArch() u32 {
    const arch = @import("builtin").cpu.arch;
    return switch (arch) {
        .x86_64 => AUDIT_ARCH_X86_64,
        .aarch64 => AUDIT_ARCH_AARCH64,
        .x86 => AUDIT_ARCH_I386,
        .arm => AUDIT_ARCH_ARM,
        else => @compileError("Unsupported architecture for seccomp"),
    };
}

// ============================================================================
// Syscall numbers for interception
// ============================================================================

pub const SYS = struct {
    // Process syscalls
    pub const clone = 56;
    pub const clone3 = 435;
    pub const fork = 57;
    pub const vfork = 58;
    pub const execve = 59;
    pub const execveat = 322;
    pub const exit = 60;
    pub const exit_group = 231;
    pub const wait4 = 61;
    pub const waitid = 247;
    pub const getpid = 39;
    pub const getppid = 110;
    pub const gettid = 186;

    // File syscalls
    pub const open = 2;
    pub const openat = 257;
    pub const openat2 = 437;
    pub const creat = 85;
    pub const close = 3;
    pub const read = 0;
    pub const write = 1;
    pub const pread64 = 17;
    pub const pwrite64 = 18;
    pub const lseek = 8;
    pub const unlink = 87;
    pub const unlinkat = 263;
    pub const rename = 82;
    pub const renameat = 264;
    pub const renameat2 = 316;
    pub const mkdir = 83;
    pub const mkdirat = 258;
    pub const rmdir = 84;
    pub const stat = 4;
    pub const fstat = 5;
    pub const lstat = 6;
    pub const newfstatat = 262;
    pub const statx = 332;
    pub const access = 21;
    pub const faccessat = 269;
    pub const faccessat2 = 439;
    pub const readlink = 89;
    pub const readlinkat = 267;
    pub const chmod = 90;
    pub const fchmod = 91;
    pub const fchmodat = 268;
    pub const chown = 92;
    pub const fchown = 93;
    pub const lchown = 94;
    pub const fchownat = 260;
    pub const utimensat = 280;
    pub const futimesat = 261;
    pub const getdents64 = 217;
    pub const getcwd = 79;
    pub const chdir = 80;
    pub const fchdir = 81;
    pub const dup = 32;
    pub const dup2 = 33;
    pub const dup3 = 292;
    pub const fcntl = 72;
    pub const flock = 73;
    pub const fsync = 74;
    pub const fdatasync = 75;
    pub const truncate = 76;
    pub const ftruncate = 77;
    pub const link = 86;
    pub const linkat = 265;
    pub const symlink = 88;
    pub const symlinkat = 266;
    pub const mknod = 133;
    pub const mknodat = 259;

    // Memory mapping
    pub const mmap = 9;
    pub const mprotect = 10;
    pub const munmap = 11;
    pub const mremap = 25;
    pub const brk = 12;

    // Network syscalls
    pub const socket = 41;
    pub const connect = 42;
    pub const accept = 43;
    pub const accept4 = 288;
    pub const bind = 49;
    pub const listen = 50;
    pub const sendto = 44;
    pub const recvfrom = 45;
    pub const sendmsg = 46;
    pub const recvmsg = 47;
    pub const getsockopt = 55;
    pub const setsockopt = 54;
    pub const getpeername = 52;
    pub const getsockname = 51;
    pub const shutdown = 48;
    pub const socketpair = 53;

    // Random
    pub const getrandom = 318;

    // Time
    pub const clock_gettime = 228;
    pub const gettimeofday = 96;
    pub const time = 201;
    pub const nanosleep = 35;
    pub const clock_nanosleep = 230;

    // Signals
    pub const rt_sigaction = 13;
    pub const rt_sigprocmask = 14;
    pub const kill = 62;
    pub const tgkill = 234;

    // Misc
    pub const ioctl = 16;
    pub const pipe = 22;
    pub const pipe2 = 293;
    pub const eventfd = 284;
    pub const eventfd2 = 290;
    pub const epoll_create = 213;
    pub const epoll_create1 = 291;
    pub const epoll_ctl = 233;
    pub const epoll_wait = 232;
    pub const epoll_pwait = 281;
    pub const poll = 7;
    pub const ppoll = 271;
    pub const select = 23;
    pub const pselect6 = 270;
    pub const uname = 63;
    pub const arch_prctl = 158;
    pub const set_tid_address = 218;
    pub const set_robust_list = 273;
    pub const futex = 202;
    pub const prlimit64 = 302;
    pub const getrlimit = 97;
    pub const setrlimit = 160;
    pub const getuid = 102;
    pub const geteuid = 107;
    pub const getgid = 104;
    pub const getegid = 108;
    pub const getgroups = 115;
    pub const setuid = 105;
    pub const setgid = 106;
    pub const sysinfo = 99;
    pub const statfs = 137;
    pub const fstatfs = 138;
};

// ============================================================================
// Signal handling
// ============================================================================

pub const SIG = struct {
    pub const CHLD = 17;
    pub const TERM = 15;
    pub const INT = 2;
    pub const HUP = 1;
    pub const QUIT = 3;
    pub const KILL = 9;
    pub const USR1 = 10;
    pub const USR2 = 12;
};

pub const SA_RESTART = 0x10000000;
pub const SA_NOCLDSTOP = 0x00000001;
pub const SA_NOCLDWAIT = 0x00000002;
pub const SA_SIGINFO = 0x00000004;
pub const SA_RESTORER = 0x04000000;

// ============================================================================
// eventfd for synchronization
// ============================================================================

pub const EFD_SEMAPHORE = 0o00000001;
pub const EFD_CLOEXEC = linux.O.CLOEXEC;
pub const EFD_NONBLOCK = linux.O.NONBLOCK;

pub fn eventfd(initval: u32, flags: u32) !fd_t {
    const result = linux.syscall2(.eventfd2, initval, flags);
    const signed: isize = @bitCast(result);
    if (signed < 0) {
        return error.EventfdFailed;
    }
    return @intCast(result);
}

// ============================================================================
// ioctl wrapper
// ============================================================================

pub fn ioctl(fd: fd_t, request: usize, arg: usize) isize {
    const result = linux.syscall3(.ioctl, @intCast(fd), request, arg);
    return @bitCast(result);
}

// ============================================================================
// Tests
// ============================================================================

test "seccomp notification sizes" {
    // Just verify struct sizes are reasonable
    try std.testing.expect(@sizeOf(SeccompNotif) > 0);
    try std.testing.expect(@sizeOf(SeccompNotifResp) > 0);
    try std.testing.expect(@sizeOf(SeccompData) > 0);
}

test "BPF helpers" {
    const stmt = bpfStmt(BPF_LD | BPF_W | BPF_ABS, 0);
    try std.testing.expectEqual(@as(u16, BPF_LD | BPF_W | BPF_ABS), stmt.code);
    try std.testing.expectEqual(@as(u32, 0), stmt.k);

    const jmp = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, 100, 1, 0);
    try std.testing.expectEqual(@as(u16, BPF_JMP | BPF_JEQ | BPF_K), jmp.code);
    try std.testing.expectEqual(@as(u32, 100), jmp.k);
    try std.testing.expectEqual(@as(u8, 1), jmp.jt);
    try std.testing.expectEqual(@as(u8, 0), jmp.jf);
}

test "audit arch" {
    const arch = auditArch();
    try std.testing.expect(arch != 0);
}
