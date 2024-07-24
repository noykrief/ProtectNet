#!/bin/bash

DEFAULT_PREFIX="test_"
DEFAULT_NAME="newfile"

# Prompt user for the base name of the file
read -p "Enter the base name of the file you want to delete under /etc (default: $DEFAULT_NAME): " base_name
base_name=${base_name:-$DEFAULT_NAME}

# Attach 'test_' prefix
filename="${DEFAULT_PREFIX}${base_name}"

# Create the file under /etc
sudo rm "/etc/$filename"

echo "Deleted file /etc/$filename."