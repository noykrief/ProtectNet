from bcc import BPF
from datetime import datetime
import requests
import socket
import threading

# Get the hostname
hostname = socket.gethostname()

# Load eBPF programs
b_fork = BPF(src_file="fork.c")
b_file_deletion = BPF(src_file="file_deletion.c")
b_file_open = BPF(src_file="file_open.c")

def handle_fork_trace(b, hostname):
    while True:
        task, pid, cpu, flags, ts, msg = b.trace_fields(nonblocking=True)
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
                        "Type": "fork bomb",
                        "Target": f"{hostname}",
                        "Info": f"{log_entry}"
                        }
                requests.post("http://10.10.248.155:5000/data", json=log_obj)

def handle_file_deletion(cpu, data, size):
    event = b_file_deletion["events"].event(data)
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    log_entry = f"{event.pid},{event.uid},{event.comm}"
    log_obj = {
            "Time": f"{timestamp}",
            "Type": f"file deletion",
            "Target": f"{event.filename}",
            "Info": f"{log_entry}"
            }
    requests.post("http://10.10.248.155:5000/data", json=log_obj)

def handle_file_open(cpu, data, size):
    event = b_file_open["events"].event(data)
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    log_entry = f"{event.pid},{event.uid},{event.comm}"
    log_obj = {
            "Time": f"{timestamp}",
            "Type": f"file open",
            "Target": f"{event.filename}",
            "Info": f"{log_entry}"
            }
    requests.post("http://10.10.248.155:5000/data", json=log_obj)

def monitor_fork_trace():
    b_fork.attach_kprobe(event="__x64_sys_clone", fn_name="trace_fork")
    b_fork.attach_kprobe(event="__x64_sys_fork", fn_name="trace_fork")
    b_fork.attach_kprobe(event="__x64_sys_vfork", fn_name="trace_fork")

    while True:
        try:
            handle_fork_trace(b_fork, hostname)
        except KeyboardInterrupt:
            break

def monitor_file_deletion():
    b_file_deletion["events"].open_perf_buffer(handle_file_deletion)

    while True:
        try:
            b_file_deletion.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def monitor_file_open():
    b_file_open.attach_kprobe(event="do_filp_open", fn_name="trace_do_filp_open")

    b_file_open["events"].open_perf_buffer(handle_file_open)

    while True:
        try:
            b_file_open.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def main():
    # Start a thread for fork trace handling
    fork_trace_thread = threading.Thread(target=monitor_fork_trace)
    fork_trace_thread.daemon = True
    fork_trace_thread.start()

    # Start a thread for file deletion events
    file_deletion_thread = threading.Thread(target=monitor_file_deletion)
    file_deletion_thread.daemon = True
    file_deletion_thread.start()

    # Start a thread for file open events
    file_open_thread = threading.Thread(target=monitor_file_open)
    file_open_thread.daemon = True
    file_open_thread.start()

    print("Tracing forks, file deletions, and opening file events... Ctrl-C to end.")

    # Keep the main thread alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == "__main__":
    main()
