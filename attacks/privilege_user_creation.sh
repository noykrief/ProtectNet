#!/bin/bash

read -p "Enter username for privileged user (default is bob): " username
username=${username:-bob}

if id "$username" &>/dev/null; then
    echo "User '$username' already exists."
    exit 1
fi

sudo useradd -m $username

if [ $? -ne 0 ]; then
    echo "Failed to create user '$username'."
    exit 1
fi

sudo usermod -aG sudo $username

if [ $? -ne 0 ]; then
    echo "Failed to grant sudo privileges to '$username'."
    exit 1
fi

echo "User '$username' created and granted sudo privileges successfully."
