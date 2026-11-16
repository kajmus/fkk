// SPDX-License-Identifier: GPL-2.0
/*
 * fguard.bpf.c - kernel side of the file monitor (eBPF LSM, monitor-only)
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 *   process calls open()/unlink()/rename()/...
 *        |
 *        v
 *   kernel VFS code ---> security_xxx() ---> LSM hook ---> OUR eBPF PROGRAM
 *                                                              |
 *                                          fill struct event   |  (event.h)
 *                                                              v
 *                                              BPF ring buffer ("events")
 *                                                              |
 *                                                              v
 *                                       user space (libbpf, epoll, rules...)
 *
 * Why LSM hooks instead of syscall tracepoints?
 *   - LSM hooks run AFTER the kernel has copied/resolved the path, so another
 *     thread cannot swap the path under us (no TOCTOU race).
 *   - One hook covers every syscall that leads there (open, openat, openat2,
 *     io_uring, 32-bit compat, ...).
 *   - The same hooks can later DENY an operation (return -EPERM) for the
 *     `guard` mode. For now every program returns 0 = "allow", so this file
 *     only observes.
 *
 * Hooks used here:
 *   lsm/file_open       - a file is being opened (read / write / both)
 *   lsm/inode_create    - a new file is being created
 *   lsm/inode_unlink    - a file is being deleted
 *   lsm/inode_rename    - a file is being renamed / moved
 *   lsm/path_chmod      - permissions are being changed
 *   lsm/path_chown      - owner is being changed
 *
 * Two ways of getting a path (important, they differ slightly):
 *   - file_open gets a `struct file *`, so we can use bpf_d_path(). That gives
 *     the full absolute path, mount points included.
 *   - the other hooks only get a `struct dentry *` (or a struct path where
 *     bpf_d_path is not allowed). We walk dentry->d_parent upwards and glue
 *     the names together. The result is relative to the ROOT OF THE
 *     FILESYSTEM, not of the mount: a file /boot/x on a separate /boot
 *     partition shows up as "/x". Always use (dev, inode) from the event to
 *     disambiguate.
 *
 * Requirements (see the project guide, section 2.3):
 *   - kernel >= 5.7 with CONFIG_BPF_LSM=y and CONFIG_DEBUG_INFO_BTF=y
 *   - "bpf" present in the boot parameter lsm=...  (check:
 *     cat /sys/kernel/security/lsm)
 *   - CONFIG_SECURITY_PATH=y for the path_chmod / path_chown hooks
 *   - run as root (or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN for LSM attach)
 *
 * Build (x86_64):
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *   clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c fguard.bpf.c -o fguard.bpf.o
 *   bpftool gen skeleton fguard.bpf.o > fguard.skel.h
 */

#include "vmlinux.h"            /* all kernel types, generated from BTF   */
#include <bpf/bpf_helpers.h>    /* SEC(), bpf_ringbuf_*, bpf_d_path, ...  */
#include <bpf/bpf_tracing.h>    /* BPF_PROG() macro for LSM/fentry progs  */
#include <bpf/bpf_core_read.h>  /* BPF_CORE_READ() - CO-RE safe field read*/

#include "event.h"              /* shared with user space; needs __u32 etc.
                                 * from vmlinux.h, so it MUST come after it */

/* ---------------------------------------------------------------------------
 * Constants that exist as #defines in the kernel and therefore are NOT in
 * vmlinux.h. Defined by hand (values are stable kernel ABI).
 * ------------------------------------------------------------------------- */
#define F_MODE_READ     0x1     /* kernel: FMODE_READ  */
#define F_MODE_WRITE    0x2     /* kernel: FMODE_WRITE */

/* How many path components we are willing to walk (dentry -> parent -> ...).
 * Must be a compile-time constant so the verifier can prove the loop ends. */
#define MAX_PATH_DEPTH  24

/* ---------------------------------------------------------------------------
 * Configuration, filled in by user space BEFORE loading the program:
 *     skel->rodata->self_tgid = getpid();
 * `const volatile` globals live in .rodata and become constants for the
 * verifier, so unused branches are optimised away.
 * ------------------------------------------------------------------------- */
const volatile __u32 self_tgid  = 0;  /* our own PID: never report ourselves  */
const volatile __u32 target_pid = 0;  /* 0 = report everybody, else only this */

/* ---------------------------------------------------------------------------
 * Maps
 * ------------------------------------------------------------------------- */

/* Kernel -> user space event queue. One buffer shared by all CPUs, 16 MiB.
 * Size must be a power of two and a multiple of the page size. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Number of events we could NOT deliver because the ring buffer was full.
 * Per-CPU => no locking needed. User space sums all CPUs and prints it:
 * silent loss is the worst failure of a security tool. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

/* Scratch space for building a path backwards (the BPF stack has only 512
 * bytes, so a path cannot live there). The buffer is TWICE the path size on
 * purpose: it lets the verifier prove that "index (<256) + length (<256)"
 * never leaves the buffer.
 *
 * Caveat: a per-CPU buffer can in theory be clobbered if this program is
 * preempted and another BPF program on the same CPU uses the same map.
 * Acceptable for a monitor; mention it in the thesis' limitations. */
struct scratch {
    char buf[2 * MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch);
} scratch_map SEC(".maps");

/* ---------------------------------------------------------------------------
 * Helpers (all __always_inline: BPF has no cheap function calls, and
 * pointer arguments to non-inlined functions are hard on the verifier)
 * ------------------------------------------------------------------------- */

static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drops, &key);

    if (cnt)
        (*cnt)++;
}

/*
 * Reserve one slot in the ring buffer and fill the part of struct event that
 * is the same for every event type: timestamp, WHO did it (process context)
 * and the identity of the process binary.
 *
 * Returns NULL when the event should not be reported (self, PID filter) or
 * when the buffer is full. The caller must then simply return 0.
 *
 * Note: ring buffer memory is NOT zeroed. Every field we care about is
 * assigned explicitly; padding bytes may hold garbage (harmless).
 */
static __always_inline struct event *event_begin(__u32 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;     /* "PID" as users know it           */

    /* --- cheap in-kernel filtering, before we spend any more cycles --- */
    if (tgid == self_tgid)
        return NULL;                 /* never report our own activity     */
    if (target_pid && tgid != target_pid)
        return NULL;
    /* TODO: path-prefix / inode / uid "approvers" from BPF maps go here
     *       (BPF_MAP_TYPE_LPM_TRIE for prefixes, hash map for inodes). */

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return NULL;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 uid_gid = bpf_get_current_uid_gid();   /* low 32 = uid, high = gid */

    /* 1. Event metadata */
    e->timestamp_ns = bpf_ktime_get_ns();
    e->type  = type;
    e->flags = 0;

    /* 2. Process context. BPF_CORE_READ follows pointers safely (a NULL
     *    or invalid pointer yields 0 instead of crashing) and adapts struct
     *    offsets to the running kernel (CO-RE). */
    e->pid   = tgid;
    e->tid   = (__u32)pid_tgid;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->uid   = (__u32)uid_gid;
    e->gid   = uid_gid >> 32;
    e->euid  = BPF_CORE_READ(task, cred, euid.val);
    e->auid  = BPF_CORE_READ(task, loginuid.val);   /* needs CONFIG_AUDIT;
                                                      * 0xFFFFFFFF = no login */
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* Identity of the running binary: task->mm->exe_file->inode.
     * Harder to fake than comm (which any process can rename). Kernel
     * threads have no mm, so both values simply stay 0 for them. */
    e->exe_dev   = BPF_CORE_READ(task, mm, exe_file, f_inode, i_sb, s_dev);
    e->exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);

    return e;
}

/*
 * Build the path of a dentry by walking up to the filesystem root and writing
 * the names BACKWARDS into the scratch buffer:
 *
 *     buf: [ ... free ...  / e t c / s h a d o w \0 ]
 *                         ^pos                    ^buf[MAX_PATH_LEN]
 *
 * Then copy the finished string to `out` (inside the ring buffer slot).
 * Sets FLAG_PATH_TRUNCATED in *flags if the path did not fit.
 * Returns the string length including the trailing NUL, or <= 0 on error.
 */
static __always_inline long dentry_to_path(struct dentry *dentry, char *out,
                                           __u32 *flags)
{
    __u32 zero = 0;
    struct scratch *s = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!s)
        return 0;

    __u32 pos = MAX_PATH_LEN;       /* we fill the buffer from the right  */
    bool reached_root = false;

    s->buf[MAX_PATH_LEN] = '\0';    /* terminator after the last component */

    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

        /* The root dentry is its own parent. Stop there. */
        if (!parent || parent == dentry) {
            reached_root = true;
            break;
        }

        __u32 len = BPF_CORE_READ(dentry, d_name.len);
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

        len &= MAX_PATH_LEN - 1;    /* NAME_MAX is 255; also tells verifier */

        /* Need room for "/" + name. If not: path too long, give up. */
        if (len + 1 > pos)
            break;

        pos -= len + 1;
        pos &= MAX_PATH_LEN - 1;    /* no-op in practice; bounds for verifier */

        s->buf[pos] = '/';
        bpf_probe_read_kernel(&s->buf[pos + 1], len, name);

        dentry = parent;
    }

    if (!reached_root)
        *flags |= FLAG_PATH_TRUNCATED;

    /* Dentry was the root itself (nothing written): the path is "/". */
    if (pos == MAX_PATH_LEN) {
        pos = MAX_PATH_LEN - 1;
        s->buf[pos] = '/';
    }

    /* Copy "/dir/dir/name\0" to the front of the event's path field. */
    return bpf_probe_read_kernel_str(out, MAX_PATH_LEN, &s->buf[pos]);
}

/* Fill dev / inode / i_mode of a file event from an inode. If `inode` is NULL
 * the CO-RE reads fail safely and everything stays 0. */
static __always_inline void set_file_ids(struct event *e, struct inode *inode)
{
    e->file.dev    = BPF_CORE_READ(inode, i_sb, s_dev);  /* kernel dev_t enc. */
    e->file.inode  = BPF_CORE_READ(inode, i_ino);
    e->file.i_mode = BPF_CORE_READ(inode, i_mode);
}

/*
 * Common body for every hook that hands us a dentry (create, unlink, rename,
 * chmod, chown): reserve event, fill file part, build path, submit.
 *
 * `mode_hint` is used only when the dentry has no inode yet (inode_create
 * runs BEFORE the new inode is attached, so the dentry is still "negative").
 */
static __always_inline int emit_dentry_event(__u32 op, struct dentry *dentry,
                                             __u16 mode_hint)
{
    struct event *e = event_begin(FG_EVENT_FILE);
    if (!e)
        return 0;

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    e->file.op  = op;
    e->file.ret = 0;    /* LSM hooks run BEFORE the operation finishes, so the
                         * final result is unknown here: 0 = "allowed so far".
                         * (Real error codes would need an fexit probe.)     */
    if (inode) {
        set_file_ids(e, inode);
    } else {
        /* File does not exist yet: take the device from the parent dir. */
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        struct inode *dir = BPF_CORE_READ(parent, d_inode);

        e->file.dev    = BPF_CORE_READ(dir, i_sb, s_dev);
        e->file.inode  = 0;
        e->file.i_mode = mode_hint;
    }

    long n = dentry_to_path(dentry, e->file.path, &e->flags);
    e->file.path_len = n > 0 ? (__u16)n : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ===========================================================================
 * LSM PROGRAMS
 *
 * SEC("lsm/<hook>") attaches to security_<hook>() in the kernel. The
 * arguments after BPF_PROG(name, ...) are the hook's own arguments, taken
 * from include/linux/lsm_hook_defs.h. Return value: 0 = allow,
 * negative errno (e.g. -EPERM) = deny. We always return 0 => monitor-only.
 * ========================================================================= */

/* A file is being opened. Fires for every open() of every file, so this is
 * the noisiest hook: the in-kernel filters above matter most here. */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    /* f_mode already says what the caller wants to do with the file. */
    __u32 mode = BPF_CORE_READ(file, f_mode);
    __u32 op;

    if ((mode & F_MODE_READ) && (mode & F_MODE_WRITE))
        op = FG_OP_OPEN_RDWR;
    else if (mode & F_MODE_WRITE)
        op = FG_OP_OPEN_WRITE;
    else if (mode & F_MODE_READ)
        op = FG_OP_OPEN_READ;
    else
        return 0;   /* O_PATH and similar: no data access, ignore */

    struct event *e = event_begin(FG_EVENT_FILE);
    if (!e)
        return 0;

    e->file.op  = op;
    e->file.ret = 0;
    set_file_ids(e, BPF_CORE_READ(file, f_inode));

    /* Preferred: kernel resolves the full path (with mount points) for us.
     * Returns the string length incl. NUL, or a negative errno. */
    long n = bpf_d_path(&file->f_path, e->file.path, MAX_PATH_LEN);
    if (n < 0) {
        /* e.g. -ENAMETOOLONG: fall back to the dentry walk (gives a
         * filesystem-relative path and sets FLAG_PATH_TRUNCATED if cut). */
        n = dentry_to_path(BPF_CORE_READ(file, f_path.dentry),
                           e->file.path, &e->flags);
    }
    e->file.path_len = n > 0 ? (__u16)n : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* A new file is about to be created in directory `dir`. Fires from
 * open(O_CREAT), creat(), mknod() of regular files. The follow-up open of the
 * new file shows up separately as lsm/file_open. */
SEC("lsm/inode_create")
int BPF_PROG(lsm_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode)
{
    return emit_dentry_event(FG_OP_CREATE, dentry, mode);
}

/* A file is about to be deleted (unlink, unlinkat, rm). */
SEC("lsm/inode_unlink")
int BPF_PROG(lsm_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    return emit_dentry_event(FG_OP_UNLINK, dentry, 0);
}

/* A file is about to be renamed or moved (rename, renameat2, mv).
 *
 * struct event has only ONE path slot, so we report the OLD name here.
 * TODO: decide how to carry the new name - either add a second path field to
 * event.h, or submit a second event for new_dentry. */
SEC("lsm/inode_rename")
int BPF_PROG(lsm_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry)
{
    return emit_dentry_event(FG_OP_RENAME, old_dentry, 0);
}

/* chmod / fchmod. Needs CONFIG_SECURITY_PATH. These hooks receive a
 * `struct path`, and bpf_d_path() is not permitted here, so we use the dentry
 * of the path and the same walk as above. */
SEC("lsm/path_chmod")
int BPF_PROG(lsm_path_chmod, const struct path *path, umode_t mode)
{
    return emit_dentry_event(FG_OP_CHMOD, BPF_CORE_READ(path, dentry), 0);
}

/* chown / fchown / lchown. Needs CONFIG_SECURITY_PATH. (The new uid/gid
 * arguments are ignored: event.h has no field for them yet.) */
SEC("lsm/path_chown")
int BPF_PROG(lsm_path_chown, const struct path *path)
{
    return emit_dentry_event(FG_OP_CHOWN, BPF_CORE_READ(path, dentry), 0);
}

/* The kernel refuses to load LSM programs that are not GPL-compatible. */
char LICENSE[] SEC("license") = "GPL";