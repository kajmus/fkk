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

#include "limits.h"

#ifndef __EVENT_H
#define __EVENT_H

struct event{
    // char type;
    int pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif