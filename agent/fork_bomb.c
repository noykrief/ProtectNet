#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(fork_count, u32, u64);

int trace_fork(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0, *count;

    count = fork_count.lookup_or_init(&pid, &zero);
    (*count)++;

    // Print information when the count exceeds a threshold
    if (*count > 10) {
        bpf_trace_printk("%u %u %llu", pid, bpf_get_current_pid_tgid(), *count);
    }

    return 0;
}

