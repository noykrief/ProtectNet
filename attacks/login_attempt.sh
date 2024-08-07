#!/bin/bash

read -p "Enter the IP address: " IP_ADDRESS

# Check if the IP address is not empty
if [ -z "$IP_ADDRESS" ]; then
    echo "IP address cannot be empty. Exiting."
    exit 1
fi

# SSH into the provided IP address
ssh "$IP_ADDRESS"

