#!/bin/bash

create_child_process() {
	sleep 9999 &
	child_pid=$!
	echo "Created child process with PID: $child_pid"
}

trap 'kill $(jobs -p); exit' SIGINT SIGRERM

while true
do
	create_child_process
	sleep 1
done
