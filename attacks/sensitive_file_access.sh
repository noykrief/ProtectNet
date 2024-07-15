#!/bin/bash

read -p "Please enter the path of the secured file you want to try to read [/etc/shadow]: " file_path

file_path=${file_path:-/etc/shadow}

if [ ! -e "$file_path" ]; then
  echo "Error: The file '$file_path' does not exist."
  exit 1
fi

if cat "$file_path" &> /dev/null; then
  echo "Error: You have permission to read the file '$file_path'."
  exit 1
else
  echo "Permission denied: You do not have permission to read the file '$file_path'."
fi
