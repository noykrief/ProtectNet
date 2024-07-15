#!/bin/bash

if ! command -v nmap &> /dev/null
then
    echo "nmap could not be found, please install nmap to proceed."
    exit 1
fi

read -p "Enter the target IP address [default: 127.0.0.1]: " target_ip
target_ip=${target_ip:-127.0.0.1}

read -p "Enter the port range [default: 1024-65535]: " port_range
port_range=${port_range:-1024-65535}

echo "Scanning $target_ip for open ports in the range $port_range..."
nmap -p $port_range $target_ip

echo "Port scan complete."

