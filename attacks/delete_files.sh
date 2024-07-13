#!/bin/bash

DEFAULT_FILE_PREFIX="file"
DEFAULT_DIR="/tmp"

read -p "What is your file prefix? (default: $DEFAULT_FILE_PREFIX): " file_prefix
file_prefix=${file_prefix:-$DEFAULT_FILE_PREFIX}

read -p "Which directory do you want them to be deleted from? (default: $DEFAULT_DIR): " directory
directory=${directory:-$DEFAULT_DIR}

mkdir -p "$directory"

rm -f "${directory}/${file_prefix}"*

echo "Deleted all required files in the directory $directory."