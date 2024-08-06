from bcc import BPF
from datetime import datetime
import requests
import socket
import threading
import ctypes
import subprocess
import pwd

# Define the event data structure in ctypes
class Event(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("count", ctypes.c_uint64),
    ]

# Get the hostname
hostname = subprocess.run("hostname -I | awk '{print $1}'", shell=True, capture_output=True, text=True).stdout.strip()

# Load eBPF programs
b_fork_bomb = BPF(src_file="fork_bomb.c")
b_file_creation = BPF(src_file="file_creation.c")
b_port_scan = BPF(src_file="port_scan.c")
b_login_attempt = BPF(src_file="login_attempt.c")
b_sudo_command = BPF(src_file="sudo_command.c")

def send_metrics(log_entry):
    print(log_entry)
    #requests.post("http://10.10.248.155:5000/data", json=log_obj)

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
                timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
                
                log_entry = f"PID {log_pid} forked {log_count} subprocesses on {hostname} at {timestamp}"
                send_metrics(log_entry)

def handle_file_creation(cpu, data, size):
    event = b_file_creation["events"].event(data)
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    filename = event.filename.decode('utf-8')
    username = pwd.getpwuid(event.uid).pw_name
    log_entry = f"User {username} with UID {event.uid} created file {filename} on {hostname} at {timestamp}"
    send_metrics(log_entry)

def handle_port_scan(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    source_ip = socket.inet_ntoa(ctypes.c_uint32(event.src_ip).value.to_bytes(4, 'little'))
    log_entry = f"Host {source_ip} scanned {event.count} ports on {hostname} at {timestamp}"
    send_metrics(log_entry)

def handle_login_attempt(cpu, data, size):
    event = b_login_attempt["events"].event(data)
    timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    username = pwd.getpwuid(event.uid).pw_name
    log_entry = f"User {username} with UID {event.uid} successfully logged-in via SSH to {hostname} at {timestamp}"
    send_metrics(log_entry)

def handle_sudo_command(cpu, data, size):
    event = b_sudo_command["events"].event(data)
    if event.uid != 0:
        timestamp = str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
        command = subprocess.run(f"ps -p {event.pid} -o args --no-headers", shell=True, capture_output=True, text=True).stdout.strip()
        username = pwd.getpwuid(event.uid).pw_name
        log_entry = f"User {username} with UID {event.uid} executed command '{command}' on {hostname} at {timestamp}"
        send_metrics(log_entry)

def monitor_fork_bomb_trace():
    b_fork_bomb.attach_kprobe(event="__x64_sys_clone", fn_name="trace_fork")
    b_fork_bomb.attach_kprobe(event="__x64_sys_fork", fn_name="trace_fork")
    b_fork_bomb.attach_kprobe(event="__x64_sys_vfork", fn_name="trace_fork")

    while True:
        try:
            handle_fork_bomb_trace(b_fork_bomb, hostname)
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

def monitor_login_attempt():
    b_login_attempt.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

    b_login_attempt["events"].open_perf_buffer(handle_login_attempt)

    while True:
        try:
            b_login_attempt.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def monitor_sudo_command():
    b_sudo_command.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

    b_sudo_command["events"].open_perf_buffer(handle_sudo_command)

    while True:
        try:
            b_sudo_command.perf_buffer_poll()
        except KeyboardInterrupt:
            break

def main():
    # Start a thread for fork trace handling
    fork_bomb_trace_thread = threading.Thread(target=monitor_fork_bomb_trace)
    fork_bomb_trace_thread.daemon = True
    fork_bomb_trace_thread.start()

    # Start a thread for file open events
    file_creation_thread = threading.Thread(target=monitor_file_creation)
    file_creation_thread.daemon = True
    file_creation_thread.start()

    # Start a thread for port scan events
    port_scan_thread = threading.Thread(target=monitor_port_scan)
    port_scan_thread.daemon = True
    port_scan_thread.start()

    # Start a thread for login attempt events
    login_attempt_thread = threading.Thread(target=monitor_login_attempt)
    login_attempt_thread.daemon = True
    login_attempt_thread.start()

    # Start a thread for sudo command events
    sudo_command_thread = threading.Thread(target=monitor_sudo_command)
    sudo_command_thread.daemon = True
    sudo_command_thread.start()

    print("Tracing cybersecurity events... Ctrl-C to end.")

    # Keep the main thread alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == "__main__":
    main()
