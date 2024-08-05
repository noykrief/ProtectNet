#!/bin/bash

create_child_process() {
	sleep 9999 &
	child_pid=$!
	echo "Created child process with PID: $child_pid"
}

trap 'kill $(jobs -p); exit' SIGINT SIGTERM

while true
do
	for i in $(seq 1 10);
	do
		create_child_process
	done
	sleep 2
done
