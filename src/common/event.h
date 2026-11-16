// THE contract between kernel and user space
// This one header is the most important file in the project, because kernel code and user code must agree on its bytes exactly. Decide it early, change it deliberately.
// Fields for the first version:
// • type: file event, exec, exit. They share one ring buffer, so the type comes first and user space switches on it.
// • timestamp: monotonic nanoseconds from the kernel. Convert to wall-clock time in user space only (util/time).
// • tgid and tid, uid: who did it.
// • cgroup id: free context for containers later.
// • comm: the 16-byte process name.
// • op: an enum (open for read, open for write, create, unlink, rename, and so on). Add values; never renumber existing ones.
// • flags: a bitmask, with at least one bit for path truncated.
// • device and inode: for matching and for disambiguating renames later.
// • path length and path: a fixed-size buffer to start with (256 bytes is enough to learn; raise it later), plus the real length.
// Rules for this header:
// • Use fixed-width integer types only, order fields largest-first, and add an explicit size check (_Static_assert on sizeof) so a layout change breaks the build instead of corrupting data silently.
// • Rename needs two paths. Decide when you reach that step; the simplest option is a second path field that only rename uses.
// • Look at how libbpf-bootstrap shares its event header between the .bpf.c and the user-space file. Copy that pattern.
// • Keep a small schema version in the JSON output. It costs nothing now and saves your replay tests later.

// #include "limits.h"

// #ifndef __EVENT_H
// #define __EVENT_H

// struct event{
//     // type defaults to open so only capture exit
// 	unsigned exit_code;
// 	bool exit_event;
//     int pid;
//     int ppid;
//     int tgid;
// 	char comm[TASK_COMM_LEN];
// 	char filename[MAX_FILENAME_LEN];
// 	unsigned long long duration_ns;
//     // inode;
//     // user


// };

// #endif

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#ifndef __EVENT_H
#define __EVENT_H

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

enum fkk_event_type {
    FKK_EVENT_FILE = 1,
    FKK_EVENT_EXEC = 2,
    FKK_EVENT_EXIT = 3,
};

enum fkk_file_op {
    FKK_OP_OPEN_READ   = 1,
    FKK_OP_OPEN_WRITE  = 2,
    FKK_OP_OPEN_RDWR   = 3,
    FKK_OP_CREATE      = 4,
    FKK_OP_UNLINK      = 5,
    FKK_OP_RENAME      = 6,
    FKK_OP_CHMOD       = 7,
    FKK_OP_CHOWN       = 8,
};

/* Bitmaska dla pola flags */
#define FLAG_PATH_TRUNCATED    (1U << 0) /* Ścieżka ucięta do MAX_PATH_LEN */
#define FLAG_BLOCKED_BY_GUARD  (1U << 1) /* Dostęp zablokowany przez Twój eBPF LSM */
#define FLAG_STDIO_IS_SOCKET   (1U << 2) /* FD 0/1/2 wskazuje na socket (Reverse Shell!) */
#define FLAG_SUID_EXEC         (1U << 3) /* Uruchomienie z SUID/SGID */

struct event {
    /* 1. Metadane zdarzenia */
    __u64 timestamp_ns;          /* bpf_ktime_get_ns() */
    __u32 type;                  /* enum event_type */
    __u32 flags;                 /* FLAG_* bitmask */

    /* 2. Kontekst procesu (KTO to zrobił) */
    __u32 pid;                   /* TGID w nomenklaturze kernela (PID w user-space) */
    __u32 tid;                   /* PID w nomenklaturze kernela (ID wątku) */
    __u32 ppid;                  /* Parent TGID - kluczowe dla drzewa procesów */
    __u32 uid;                   /* Real UID */
    __u32 euid;                  /* Effective UID */
    __u32 gid;                   /* Real GID */
    __u32 auid;                  /* Audit Login UID (-1 dla demonów np. nginx) */
    __u64 cgroup_id;             /* Identyfikacja kontenera Docker/K8s */

    /* Niepodrabialna tożsamość binarki procesu (task->mm->exe_file->f_inode) */
    __u32 exe_dev;
    __u64 exe_inode;
    char  comm[TASK_COMM_LEN];   /* Nazwa procesu z task_struct */

    /* 3. Dane specyficzne dla typu zdarzenia */
    union {
        struct {
            __u32 op;            /* enum file_op */
            __s32 ret;           /* 0 = sukces, <0 = kod błędu (np. -EACCES, -EPERM) */
            __u32 dev;           /* Urządzenie docelowego pliku (s_dev) */
            __u64 inode;         /* Inode docelowego pliku (i_ino) */
            __u16 i_mode;        /* Typ pliku (REG, DIR, SOCK) + uprawnienia (0644) */
            __u16 path_len;      /* Długość zwrócona przez bpf_d_path */
            char  path[MAX_PATH_LEN];
        } file;

        struct {
            __s32 ret;
            __u32 stdin_inode;   /* Inode deskryptora 0 (do korelacji z socketem) */
            __u16 path_len;
            char  filename[MAX_PATH_LEN];
        } exec;

        struct {
            __s32 exit_code;
        } exit;
    };
};

#endif /* __EVENT_H */