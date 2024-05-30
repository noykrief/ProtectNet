from bcc import BPF
from time import sleep
import socket
import time

# Get the hostname
hostname = socket.gethostname()

# Define eBPF program
prog = """
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
        bpf_trace_printk("%u %u %llu\\n", pid, bpf_get_current_pid_tgid(), *count);
    }

    return 0;
}
"""

# Load eBPF program
b = BPF(text=prog)
b.attach_kprobe(event="__arm64_sys_clone", fn_name="trace_fork")
b.attach_kprobe(event="__arm64_sys_fork", fn_name="trace_fork")
b.attach_kprobe(event="__arm64_sys_vfork", fn_name="trace_fork")

print("Tracing forks... Hit Ctrl-C to end.")

# Open the csv file
csvfile = open("metrics.csv", "a")

# Print the output
while True:
    try:
        sleep(1)
    except KeyboardInterrupt:
        csvfile.close()
        exit()
    # Read trace pipe
    while True:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking=True)
        if msg:
            # Parse the message
            parts = msg.split()
            if len(parts) == 3:
                log_pid = int(parts[0])
                log_tgid = int(parts[1])
                log_count = int(parts[2])
                # Get current time
                timestamp = int(time.time())
                # Log the metrics
                log_entry = f"{timestamp}, {log_pid}, {log_tgid}, {hostname}, {log_count}\n"
                print(log_entry.strip())
                csvfile.write(log_entry)
        else:
            break
