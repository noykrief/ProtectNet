#!/bin/bash

DEFAULT_NUM_FILES=1000
DEFAULT_DIR="/tmp"

read -p "How many files do you want to create? (default: $DEFAULT_NUM_FILES): " num_files
num_files=${num_files:-$DEFAULT_NUM_FILES}

read -p "Which directory do you want them to be created in? (default: $DEFAULT_DIR): " directory
directory=${directory:-$DEFAULT_DIR}

mkdir -p "$directory"

for i in $(seq 1 $num_files); do
    touch "${directory}/file${i}"
done

echo "Created $num_files files in the directory $directory."