# This will be the file where the chatGPT integrstion will happen and all functionswill be written here

import os
import csv
import time
import requests
from openai import OpenAI
from dotenv import load_dotenv


# Load environemnt variables for interacting with ChatGPT
load_dotenv()
OPENAI_API_KEY=os.getenv("OEPNAI_API_KEY")

def generate_insights(ebpf_info):
  client = OpenAI(api_key=OPENAI_API_KEY)
  potential_threats = []

  completion = client.chat.completions.create(
    model="gpt-3.5-turbo-0125",
    messages=[
      {
        "role": "system",
        "content": "You are a helpful assistant designed to identify security threats, anomalies and performance issues"
        "from a streaming data (parameters from function call every few seconds) of system calls, network and kernel" 
        "information collected through eBPF agents.",
      },
      {
        "role": "system",
        "content": "For each data you get, go through these steps: \n"
        "1. Print every log containing a suspicious method that can be a potential security threat.\n"
        "2. The header of your response should be:\nTime: 'timestamp',\nType: 'log_type',\nHost: 'hostname',\n"
        "Severity: LOW/MEDIUM/HIGH/CRITICAL,\nInfo: 'information',\nAction Items: 'action_items'.\n"
        "Severity should be chosen wisely from the list, according to the potential threat of the log."
        "Info should contain your inferred explanation in simple words of what the log says (what is the problem)."
        "Action Items should contain technical steps needed to perform in order to solve the problem (you will provide them)."
        "3. Gather same logs from different hostnames together if the problem looks the same or you infer a wide"
        "security problem. Gather logs the repeat in logs several times on the same hostname.\n The header of these kind of response should be:\nTime: 'timestamp',\n"
        "Type: 'log_type',\nHost: 'hostname',\nPotential Severity: LOW/MEDIUM/HIGH/CRITICAL,\nLead: 'lead',\nInfo: 'information'.\n"
        "Potential Severity should be chosen wisely from the list, according to the potential threat you infer might be."
        "Lead should contain a short explanation of all gathered look-alike logs, inffered by you."
        "Info should contain your inferred more detailed information about the potential threat and a suggestion for an action item."
        "Mention in header all hostnames relevant.\n"
        "4. Censor passwords in the output.\n"
      },
      {
        "role": "user",
        "content": "Time: 2024-04-15T12:45:23Z\nType: System Call\nHost: 192.168.1.101\nInfo: 501, execve, /usr/local/bin/suspicious_script.sh"
      },
      {
        "role": "assistant",
        "content": "Time: 2024-04-15T12:45:23Z\nType: System Call\nHost: 192.168.1.101\nSeverity: HIGH\n"
        "Info: User 501 called 'execve' on '/usr/local/bin/suspicious_script.sh', potentially harmful behavior detected.\n"
        "Action Items: 1. Terminate the process assosiated with the system call by running `kill -9 {pid}`.\n"
        "2. Quarantine the file suspicious_script.sh by running `mv /usr/local/bin/suspicious_script.sh /quarantine/`.\n"
        "For long term prevention, umplement the following actions:\n1. Change permissions on the quarantined script by running "
        "`chmod 700 /quarantine/suspicious_script.sh`.\n2. Deploy intrusion detection/prevention systems like snort."
      },
      {
        "role": "user",
        "content": "Time: 2024-04-15T12:50:00Z\nType: System Call\nHost: 192.168.1.105\nInfo: Failed SSH connection from PID 1234"
      },
      {
        "role": "user",
        "content": "Time: 2024-04-15T12:50:26Z\nType: System Call\nHost: 192.168.1.105\nInfo: Failed SSH connection from PID 1244"
      },
      {
        "role": "user",
        "content": "Time: 2024-04-15T12:51:00Z\nType: System Call\nHost: 192.168.1.105\nInfo: Failed SSH connection from PID 4834"
      },
      {
        "role": "assistant",
        "content": "Time: 2024-04-15T12:51:00Z\nType: System Call\nPotential Severity: CRITICAL\nLead: Multiple login attempts detected "
        "from IP 192.168.1.105\nInfo: Over 20 failed login attempts in the last 5 minutes. Consider investigation the source IP and "
        "applying IP-based blocking or rate limiting.\n To block this IP using iptables, use the following command: `sudo iptables -A INPUT -s 192.168.1.105 -j DROP`"
      },
      {
        "role": "user",
        "content": ""
      },
      {
        "role": "assistant",
        "content": "Time: ###\nType: ###\nHost: ###\nSeverity: ###\nInfo: ###\nAction Items: ###"
      },
      {
        "role": "user",
        "content": ""
      },
      {
        "role": "assistant",
        "content": "Time: ###\nType: ###\nHost: ###\nSeverity: ###\nInfo: ###\nAction Items: ###"
      },
      {
        "role": "user",
        "content": f"{ebpf_info}"
      },
    ],
  )

  return (
    completion.choices[0].message.content + "\n---------------------------------\n"
  )
  

# POC Part - main function in order to be able to send data without the API from the agent.

def main():
  system_calls = []

  # file to open after running the agent and saving data to a file for POC
  with open("./ebpf_info.csv", newline="") as csvfile:
    csv_reader = csv.reader(csvfile)
    for row in csv_reader:
      system_calls.append(row)

  if system_calls:
    print("Starting to analyze you data...")

    potential_threats = []

    for i, syscall in enumerate(system_calls, start=1):
      print(f"\n({i}/{len(system_calls)})")

      potential_threats.append(generate_insights(syscall))

    print("Printing insights results...")
    for syscall in potential_threats:
      print(syscall)
    
if __name__ == "__main__":
  main()