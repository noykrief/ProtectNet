from bcc import BPF
from time import sleep
from os import environ as env
from datetime import datetime
import requests
import socket
import time
import json
import csv

# Get the hostname
hostname = socket.gethostname()

# Load eBPF program
b = BPF(src_file="fork_bomb.c")
b.attach_kprobe(event="__x64_sys_clone", fn_name="trace_fork")
b.attach_kprobe(event="__x64_sys_fork", fn_name="trace_fork")
b.attach_kprobe(event="__x64_sys_vfork", fn_name="trace_fork")

print("Tracing forks... Hit Ctrl-C to end.")

# Print the output
while True:
    try:
        sleep(1)
    except KeyboardInterrupt:
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
                timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
                # Log the metrics
                log_entry = f"{log_pid},{log_tgid},{log_count}"
                log_obj = {
                        "Time": f"{timestamp}",
                        "Type": "system call",
                        "Host": f"{hostname}",
                        "Info": f"{log_entry}"
                        }
                print(log_entry.strip())
                requests.post("http://10.10.248.155:5000", json=log_obj)
        else:
            break
