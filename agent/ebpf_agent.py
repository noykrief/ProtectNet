from bcc import BPF
from time import sleep
from os import environ as env
from datetime import datetime
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

# Open the csv file and write the headers of the file
headers = ["Time","Type","Host","Info"]
csvfile = open(f"metrics.csv", "a")
writer = csv.DictWriter(csvfile, fieldnames=headers)
writer.writeheader()

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
                writer.writerow(log_obj)
        else:
            break
