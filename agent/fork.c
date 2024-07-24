#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(fork_count, u32, u64);
BPF_PERF_OUTPUT(events);

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