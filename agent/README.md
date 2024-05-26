# Fork Bomb Detection Script

## Script Explanation

This script uses eBPF (extended Berkeley Packet Filter) to monitor and detect potential fork bomb activities on a Linux system. A fork bomb is characterized by rapid and excessive creation of child processes, which can overwhelm system resources. The script tracks process creation events and logs metrics when a process exceeds a specified threshold for forking activity.

### Logged Metrics

Logs are written into `metrics.log` as well is being printed to the console.
- **timestamp:** Unix timestamp of the log entry.
- **pid:** Process ID of the forking process.
- **tgid:** Thread Group ID.
- **hostname:** Hostname of the system.
- **amount of subprocesses:** Number of subprocesses created by the process.

## Dependencies and Installation Instructions

### Dependencies

- **Python 3**
- **BCC (BPF Compiler Collection)**
- **Linux headers** matching your kernel version

### Installation

#### For Ubuntu/Debian

1. **Update your package list:**
    ```bash
    sudo apt-get update
    ```

2. **Install BCC and its dependencies:**
    ```bash
    sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
    ```

3. **Install Python3 and pip3 if not already installed:**
    ```bash
    sudo apt-get install python3 python3-pip
    ```

4. **Install the BCC Python bindings:**
    ```bash
    sudo pip3 install bcc numba
    ```

#### For Fedora/CentOS

1. **Install BCC and its dependencies:**
    ```bash
    sudo dnf install bcc bcc-tools python3-bcc linux-headers-$(uname -r)
    ```

2. **Install Python3 and pip3 if not already installed:**
    ```bash
    sudo dnf install python3 python3-pip
    ```

3. **Install the BCC Python bindings:**
    ```bash
    sudo pip3 install bcc numba
    ```

## Check Architecture for kprobes

This script uses kprobes to attach eBPF programs to system calls. Ensure your system supports kprobes by checking the architecture:

1. **Check the architecture:**
    ```bash
    uname -m
    ```

2. **Supported architectures:**
    - **x86_64**
    - **arm64** (or aarch64)
	
3. **Support kernel modules:**
    Validate supported kprobes for kernel arch.
   ```bash
   egrep 'sys_clone|sys_fork' /proc/kallsyms
   ```
   
   Change it accordingly under "Load eBPF program" section in `ebpf_agent.py`.

If your architecture is supported, you can proceed to run the script.

## Running the Script

1. **Export python path:**
   ```bash
   export PYTHONPATH=$(dirname `find /usr/lib -name bcc`):$PYTHONPATH
   ```


2. **Make the script executable (optional):**
    ```bash
    chmod +x ebpf_agent.py
    ```

3. **Run the script with root privileges:**
    ```bash
    sudo python3 ebpf_agent.py
    ```

The script will start tracing process creation events and log entries when the forking threshold is exceeded.

## Testing the Script

1. In another terminal / in the background, run `fork_bomb.sh` example script to simulate a fork bomb.

2. Run the `ebpf_agent.py` script and expect the fork bomb to be captured.