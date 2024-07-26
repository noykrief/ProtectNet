#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/cred.h>

#define MAX_FILENAME_LEN 256

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u64 timestamp;
};

int trace_do_filp_open(struct pt_regs *ctx, int dfd, const struct filename *name, int flags, umode_t mode) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    data.pid = pid;
    data.uid = uid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_str(&data.filename, sizeof(data.filename), (void *)name->name);

    if (data.filename[0] == '/' && data.filename[1] == 'e' && data.filename[2] == 't' && data.filename[3] == 'c' &&
        data.comm[0] == 't' && data.comm[1] == 'o' && data.comm[2] == 'u' && data.comm[3] == 'c' && data.comm[4] == 'h' &&
        data.comm[5] == '\0') {

        // Exclude "/etc/ld.so.cache"
        if (data.filename[0] != '/' || data.filename[1] != 'e' || data.filename[2] != 't' || data.filename[3] != 'c' || 
            data.filename[4] != '/' || data.filename[5] != 'l' || data.filename[6] != 'd' || data.filename[7] != '.' || 
            data.filename[8] != 's' || data.filename[9] != 'o' || data.filename[10] != '.' || data.filename[11] != 'c' ||
            data.filename[12] != 'a' || data.filename[13] != 'c' || data.filename[14] != 'h' || data.filename[15] != 'e' ||
            data.filename[16] != '\0') {
            events.perf_submit(ctx, &data, sizeof(data));
        }
    }

    return 0;
}
