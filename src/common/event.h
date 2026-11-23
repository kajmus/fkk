#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#ifndef __EVENT_H
#define __EVENT_H

#include "limits.h"
// #define TASK_COMM_LEN 16
// #define MAX_PATH_LEN  256

enum fkk_event_type {
    FKK_EVENT_FILE = 1,
    FKK_EVENT_EXEC = 2,
    FKK_EVENT_EXIT = 3,
};

enum fkk_file_op {
    FKK_OP_UNKNOWN     = 0,
    FKK_OP_OPEN_READ   = 1,
    FKK_OP_OPEN_WRITE  = 2,
    FKK_OP_OPEN_RDWR   = 3,
    FKK_OP_CREATE      = 4,
    FKK_OP_UNLINK      = 5,
    FKK_OP_RENAME      = 6,
    FKK_OP_CHMOD       = 7,
    FKK_OP_CHOWN       = 8,
    FKK_OP_MAX,
};

/* Bitmaska dla pola flags */
#define FLAG_PATH_TRUNCATED    (1U << 0) /* Ścieżka ucięta do MAX_PATH_LEN */
#define FLAG_BLOCKED_BY_GUARD  (1U << 1) /* Dostęp zablokowany przez Twój eBPF LSM */
#define FLAG_STDIO_IS_SOCKET   (1U << 2) /* FD 0/1/2 wskazuje na socket (Reverse Shell!) */
#define FLAG_SUID_EXEC         (1U << 3) /* Uruchomienie z SUID/SGID */

struct event {
    // metadata
    __u64 timestamp_ns;          /* bpf_ktime_get_ns() */
    __u32 type;                  /* enum event_type */
    __u32 flags;                 /* FLAG_* bitmask */
    
    // procces info 
    __u32 pid;                   /* TGID w nomenklaturze kernela (PID w user-space) */
    __u32 tid;                   /* PID w nomenklaturze kernela (ID wątku) */
    __u32 ppid;                  /* Parent TGID - kluczowe dla drzewa procesów */
    __u32 uid;                   /* Real UID */
    __u32 euid;                  /* Effective UID */
    __u32 gid;                   /* Real GID */
    __u32 auid;                  /* Audit Login UID (-1 dla demonów np. nginx) */
    __u64 cgroup_id;             /* Identyfikacja kontenera Docker/K8s */

    //  precises identification 
    __u32 exe_dev;
    __u64 exe_inode;
    char  comm[TASK_COMM_LEN];   // file/program name

    // type specific
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
            __u32 stdin_inode;   // for sockets
            __u16 path_len;
            char  filename[MAX_PATH_LEN];
        } exec;

        struct {
            __s32 exit_code;
        } exit;
    };
};

#endif