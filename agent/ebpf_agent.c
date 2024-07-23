#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/cred.h>

#define MAX_FILENAME_LEN 256

BPF_HASH(fork_count, u32, u64);
BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u64 timestamp;
};

int trace_fork(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0, *count;

    count = fork_count.lookup_or_init(&pid, &zero);
    (*count)++;

    if (*count > 10) {
        bpf_trace_printk("%u %u %llu\n", pid, bpf_get_current_pid_tgid(), *count);
    }

    return 0;
}


int kprobe__do_unlinkat(struct pt_regs *ctx, int dfd, struct filename *name) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    data.pid = pid;
    data.uid = uid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_str(&data.filename, sizeof(data.filename), (void *)name->name);

    if (data.filename[0] == '/' && data.filename[1] == 'e' && data.filename[2] == 't' && data.filename[3] == 'c') {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

