#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

struct event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char args[128];
};

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv, const char __user *const __user *envp) {
    struct event_t event = {};

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (event.comm[0] != 's' || event.comm[1] != 's' || event.comm[2] != 'h' || event.comm[3] != 'd') {
        return 0;
    }

    event.pid = pid;
    event.uid = uid;

    bpf_probe_read_user_str(event.args, sizeof(event.args), (void *)argv[0]);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

