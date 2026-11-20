#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common/event.h"


char LICENSE[] SEC("license") = "GPL";

// consts from kernel
#define F_MODE_READ     0x1
#define F_MODE_WRITE    0x2
// requiared by verifer
#define MAX_PATH_DEPTH  24

// temp values later fetched from user space
// to not include our program
const volatile __u32 self_tgid  = 0;
// 0 for everone else this specific one (maybe change this later for mulltiple?)
const volatile __u32 target_pid = 0;


//  MAPS -------------------------------------

// event queue for sending info to user space ,one for all cpus
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// skiped or droped events for reasons like full ringbuffer 
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, FKK_OP_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

// map+struct for Extending path lenght
struct e_path {
    char buf[2 * MAX_PATH_LEN];
};
//  can be used by other programs  indirectly
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct e_path);
} e_path_map SEC(".maps");


static __always_inline void count_drop(__u32 op){
    __u32 key = (op < FKK_OP_MAX) ? op:0;
    __u64 *cnt = bpf_map_lookup_elem(&drops, &key);
    if (cnt) __sync_fetch_and_add(cnt,1);
}
static __always_inline struct event *event_begin(__u32 type, __u32 op){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (tgid == self_tgid)
        return NULL;
    if (target_pid && tgid != target_pid)
        return NULL;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_drop(op);
        return NULL;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = type;
    e->flags = 0;

    e->pid = tgid;
    e->tid = (__u32)pid_tgid;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->uid   = (__u32)uid_gid;
    e->gid   = uid_gid >> 32;
    e->euid  = BPF_CORE_READ(task, cred, euid.val);
    e->auid  = BPF_CORE_READ(task, loginuid.val);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->exe_dev   = BPF_CORE_READ(task, mm, exe_file, f_inode, i_sb, s_dev);
    e->exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);

    return e;
}
static __always_inline long dentry_to_path(struct dentry *dentry, char *out, __u32 *flags){
    __u32 zero = 0;
    struct e_path *s = bpf_map_lookup_elem(&e_path_map, &zero);
    if (!s)
        return 0;

    __u32 pos = MAX_PATH_LEN;
    bool reached_root = false;
    s->buf[MAX_PATH_LEN] = '\0';

    for (int i=0; i < MAX_PATH_DEPTH; i++){
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (!parent || parent == dentry){
            reached_root = true;
            break;
        }
        __u32 len = BPF_CORE_READ(dentry, d_name.len);
        const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

        len &= MAX_PATH_LEN -1;
        // check for "/""
        if (len +1 > pos) break;

        pos -= len +1;
        pos &= MAX_PATH_LEN -1; // some verifier bs 
        s->buf[pos] = '/';
        bpf_probe_read_kernel(&s->buf[pos+1], len, name);
        dentry = parent;
    }

    if (!reached_root) *flags |= FLAG_PATH_TRUNCATED;
    if (pos == MAX_PATH_LEN) {
        pos = MAX_PATH_LEN -1;
        s->buf[pos] = '/';
    }

    return bpf_probe_read_kernel_str(out, MAX_PATH_LEN, &s->buf[pos]);
}

static __always_inline void set_file_ids(struct event *e, struct inode *inode){
    e->file.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    e->file.inode = BPF_CORE_READ(inode, i_ino);
    e->file.i_mode = BPF_CORE_READ(inode, i_mode);
}
static __always_inline int emit_dentry_event(__u32 op, 
    struct dentry *dentry, __u16 mode_hint){
    struct event *e = event_begin(FKK_EVENT_FILE, op);
    if (!e) return 0;

    struct inode  *inode = BPF_CORE_READ(dentry, d_inode);

    e->file.op = op;
    e->file.ret = 0;

    if(inode) set_file_ids(e, inode);
    else {
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        struct inode *dir = BPF_CORE_READ(parent, d_inode);

        e->file.dev = BPF_CORE_READ(dir, i_sb, s_dev);
        e->file.inode = 0;
        e->file.i_mode = mode_hint;
    }
    long n = dentry_to_path(dentry, e->file.path, &e->flags);
    e->file.path_len =n > 0 ? (__u16)n :0;
    bpf_ringbuf_submit(e,0);
    return 0;
}


SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file){
    __u32 mode = BPF_CORE_READ(file, f_mode);
    __u32 op;

    if ((mode & F_MODE_READ) && (mode & F_MODE_WRITE))
        op = FKK_OP_OPEN_RDWR;
    else if (mode & F_MODE_READ)
        op = FKK_OP_OPEN_READ;
    else if (mode& F_MODE_WRITE)
        op = FKK_OP_OPEN_WRITE;
    else
        return 0;

    struct event *e = event_begin(FKK_EVENT_FILE, op);
    if (!e) return 0;
    e->file.op = op;
    e->file.ret = 0;

    set_file_ids(e, BPF_CORE_READ(file, f_inode));
    long n = bpf_d_path(&file->f_path, e->file.path, MAX_PATH_LEN);
    if (n < 0) n = dentry_to_path(
        BPF_CORE_READ(file, f_path.dentry), 
        e->file.path, &e->flags);

    bpf_ringbuf_submit(e,0);
    return 0;
}


SEC("lsm/inode_create")
int BPF_PROG(lsm_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode){
    return emit_dentry_event(FKK_OP_CREATE, dentry, mode);
}
SEC("lsm/inode_unlink")
int BPF_PROG(lsm_inode_unlink, struct inode *dir, struct dentry *dentry){
    return emit_dentry_event(FKK_OP_UNLINK, dentry, 0);
}
SEC("lsm/inode_rename")
int BPF_PROG(lsm_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry){
    return emit_dentry_event(FKK_OP_RENAME, old_dentry,0);
}
SEC("lsm/path_chmod")
int BPF_PROG(lsm_path_chmod, const struct path *path, umode_t mode){
    return emit_dentry_event(FKK_OP_CHMOD,  
        BPF_CORE_READ(path, dentry),0);
}
SEC("lsm/path_chown")
int BPF_PROG(lsm_path_chown, const struct path *path){
    return emit_dentry_event(FKK_OP_CHOWN, 
        BPF_CORE_READ(path, dentry), 0);
}
