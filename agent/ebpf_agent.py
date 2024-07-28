from bcc import BPF
from datetime import datetime
import requests
import socket
import threading
import ctypes

# Define the event data structure in ctypes
class Event(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("count", ctypes.c_uint64),
    ]

# Get the hostname
hostname = socket.gethostname()

# Load eBPF programs
b_fork_bomb = BPF(src_file="fork_bomb.c")
b_file_deletion = BPF(src_file="file_deletion.c")
b_file_creation = BPF(src_file="file_creation.c")
b_port_scan = BPF(src_file="port_scan.c")

def handle_fork_bomb_trace(b, hostname):
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

def handle_file_creation(cpu, data, size):
    event = b_file_creation["events"].event(data)
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    log_entry = f"{event.pid},{event.uid},{event.comm}"
    log_obj = {
            "Time": f"{timestamp}",
            "Type": f"file creation",
            "Target": f"{event.filename}",
            "Info": f"{log_entry}"
            }
    requests.post("http://10.10.248.155:5000/data", json=log_obj)

def handle_port_scan(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    log_entry = f"{socket.inet_ntoa(ctypes.c_uint32(event.src_ip).value.to_bytes(4, 'big'))},{event.dst_port},{event.count}"
    log_obj = {
            "Time": f"{timestamp}",
            "Type": f"port scan",
            "Target": f"{hostname}",
            "Info": f"{log_entry}"
            }
    requests.post("http://10.10.248.155:5000/data", json=log_obj)

def monitor_fork_bomb_trace():
    b_fork_bomb.attach_kprobe(event="__x64_sys_clone", fn_name="trace_fork")
    b_fork_bomb.attach_kprobe(event="__x64_sys_fork", fn_name="trace_fork")
    b_fork_bomb.attach_kprobe(event="__x64_sys_vfork", fn_name="trace_fork")

    while True:
        try:
            handle_fork_bomb_trace(b_fork_bomb, hostname)
        except KeyboardInterrupt:
            break

def monitor_file_deletion():
    b_file_deletion["events"].open_perf_buffer(handle_file_deletion)

    while True:
        try:
            b_file_deletion.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def monitor_file_creation():
    b_file_creation.attach_kprobe(event="do_filp_open", fn_name="trace_do_filp_open")

    b_file_creation["events"].open_perf_buffer(handle_file_creation)

    while True:
        try:
            b_file_creation.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def monitor_port_scan():
    b_port_scan["events"].open_perf_buffer(handle_port_scan)
    fn = b_port_scan.load_func("packet_filter", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(fn, "ens160")

    while True:
        try:
            b_port_scan.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def main():
    # Start a thread for fork trace handling
    fork_bomb_trace_thread = threading.Thread(target=monitor_fork_bomb_trace)
    fork_bomb_trace_thread.daemon = True
    fork_bomb_trace_thread.start()

    # Start a thread for file deletion events
    file_deletion_thread = threading.Thread(target=monitor_file_deletion)
    file_deletion_thread.daemon = True
    file_deletion_thread.start()

    # Start a thread for file open events
    file_creation_thread = threading.Thread(target=monitor_file_creation)
    file_creation_thread.daemon = True
    file_creation_thread.start()

    # Start a thread for port scan events
    port_scan_thread = threading.Thread(target=monitor_port_scan)
    port_scan_thread.daemon = True
    port_scan_thread.start()

    print("Tracing fork bombs, file deletions, files creations and port scans events... Ctrl-C to end.")

    # Keep the main thread alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == "__main__":
    main()
