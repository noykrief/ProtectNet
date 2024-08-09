#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uio.h>

#define MAX_CMD_LEN 256

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_CMD_LEN];
    u64 timestamp;
};

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    data.pid = pid;
    data.uid = uid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read the command filename
    if (bpf_probe_read_str(data.filename, sizeof(data.filename), (void *)filename) > 0) {
        // Output the data
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

