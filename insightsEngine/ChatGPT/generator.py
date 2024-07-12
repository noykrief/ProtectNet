import os
import csv
import ast
import logging
import logging_loki
from pymongo import MongoClient

from openai import OpenAI
from colorama import Fore

# Setup Loki configurations in order to send logs        
logging_loki.emitter.LokiEmitter.level_tag = "level"

handler = logging_loki.LokiHandler(
        url="http://10.10.248.155:3100/loki/api/v1/push",
        version="1",
        )

logger = logging.getLogger("LokiLogger")

logger.addHandler(handler)

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27717/")
db = client["agents_metrics"]
collection = db["metrics"]


# The function defines the bot's purpose and sends the data for analysis
def generate_insights(ebpf_info):
  client = OpenAI()

  completion = client.chat.completions.create(
    model="gpt-3.5-turbo-0125",
    response_format={ "type": "json_object" },
    messages=[
      {
        "role": "system",
        "content": "You are a helpful assistant designed to identify security threats, anomalies and performance issues"
        "from a streaming data (parameters from function call every few seconds) of system calls, network and kernel" 
        "information collected through eBPF agents.",
      },
      {
        "role": "system",
        "content": "For each list of JSONs you get, go through these steps: \n"
        "1. Print every log containing a suspicious method that can be a potential security threat.\n"
        "2. The header of your response should be:\nTime: 'timestamp',\nLog Type: 'log_type',\nHost: 'hostname',\n"
        "Severity: NEUTRAL/LOW/MEDIUM/HIGH/CRITICAL,\nInfo: 'information',\nAction Items: 'action_items'.\n"
        "Severity should be chosen wisely from the list, according to the potential threat of the log."
        "Info should contain your inferred explanation in simple words of what the log says (what is the problem)."
        "Action Items should contain technical steps needed to perform in order to solve the problem (you will provide them)."
        "3. Gather same logs from different hostnames together if the problem looks the same or you infer a wide"
        "security problem. Gather logs the repeat in logs several times on the same hostname.\n The header of these kind of response should be:\nTime: 'timestamp',\n"
        "Log Type: 'log_type',\nHost: 'hostname',\nPotential Severity: NEUTRAL/LOW/MEDIUM/HIGH/CRITICAL,\nLead: 'lead',\nInfo: 'information'.\n"
        "Potential Severity should be chosen wisely from the list, according to the potential threat you infer might be."
        "Lead should contain a short explanation of all gathered look-alike logs, inffered by you."
        "Info should contain your inferred more detailed information about the potential threat and a suggestion for an action item."
        "Mention in header all hostnames relevant.\n"
        "4. Censor passwords in the output.\n"
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:50:00Z",
            "Log Type": "System Call",
            "Host": "192.168.1.105",
            "Info": "Failed SSH connection from PID 1234"
          },
          {
            "Time": "2024-04-15T12:50:26Z",
            "Log Type": "System Call",
            "Host": "192.168.1.105",
            "Info": "Failed SSH connection from PID 1234"
          },
          {
            "Time": "2024-04-15T12:51:03Z",
            "Log Type": "System Call",
            "Host": "192.168.1.105",
            "Info": "Failed SSH connection from PID 1234"
          },
          {
            "Time": "2024-04-15T12:51:43Z",
            "Log Type": "System Call",
            "Host": "192.168.1.105",
            "Info": "Failed SSH connection from PID 1234"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:51:00Z",
            "Log Type": "System Call",
            "Potential Severity": "CRITICAL",
            "Lead": "Multiple login attempts detected from IP 192.168.1.105",
            "Info": "Over 20 failed login attempts in the last 5 minutes.\n"
            "Consider investigation the source IP and applying IP-based blocking or rate limiting.\n"
            "To block this IP using iptables, use the following command: `sudo iptables -A INPUT -s 192.168.1.105 -j DROP`"
          }
        ])
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:45:23Z",
            "Log Type": "System Call",
            "Host": "192.168.1.101",
            "Info": "501, execve, /usr/local/bin/suspicious_script.sh"
          },
          {
            "Time": "2024-04-15T12:47:15Z",
            "Log Type": "System Call",
            "Host": "192.168.1.102",
            "Info": "502, open, /etc/passwd"
          },
          {
            "Time": "2024-04-15T12:50:10Z",
            "Log Type": "System Call",
            "Host": "192.168.1.105",
            "Info": "505, execve, /bin/cat, /etc/passwd"
          },
          {
            "Time": "2024-04-15T12:53:30Z",
            "Log Type": "System Call",
            "Host": "192.168.1.107",
            "Info": "507, open, /etc/ssh/sshd_config"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:45:23Z",
            "Log Type": "System Call",
            "Host": "192.168.1.101",
            "Severity": "HIGH",
            "Info": "User 501 called 'execve' on '/usr/local/bin/suspicious_script.sh', potentially harmful behavior detected.",
            "Action Items": [
              "Terminate the process associated with the system call by running `kill -9 1234`.",
              "Quarantine the file suspicious_script.sh by running `mv /usr/local/bin/suspicious_script.sh /quarantine/`.",
              "For long-term prevention, implement the following actions:",
              "Change permissions on the quarantined script by running `chmod 700 /quarantine/suspicious_script.sh`.",
              "Deploy intrusion detection/prevention systems like snort."
            ]
          },
          {
            "Time": "2024-04-15T12:50:10Z",
            "Log Type": "System Call",
            "Host": "192.168.1.105",
            "Severity": "NEUTRAL",
            "Info": "User 505 called 'execve' on '/bin/cat, /etc/passwd'. This action is not necessarily harmful but may warrant monitoring.",
            "Action Items": []
          },
          {
            "Time": "2024-04-15T12:53:30Z",
            "Log Type": "System Call",
            "Host": "192.168.1.107",
            "Severity": "MEDIUM",
            "Info": "User 507 called 'open' on '/etc/ssh/sshd_config'. This action could potentially expose sensitive system configuration. It requires further investigation.",
            "Action Items": [
              "Review the access control list for /etc/ssh/sshd_config to ensure appropriate permissions are set.",
              "Monitor any changes to /etc/ssh/sshd_config closely for signs of tampering or unauthorized access."
            ]
          }
        ])
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-07-01T20:06:38Z",
            "Log Type": "System Call",
            "Host": "192.168.1.110",
            "Info": "428892,428892,73"
          },
          {
            "Time": "2024-07-01T20:06:39Z",
            "Log Type": "System Call",
            "Host": "192.168.1.110",
            "Info": "428892,428892,74"
          },
          {
            "Time": "2024-07-01T20:06:40Z",
            "Log Type": "System Call",
            "Host": "192.168.1.110",
            "Info": "428892,428892,75"
          },
          {
            "Time": "2024-07-01T20:06:41Z",
            "Log Type": "System Call",
            "Host": "192.168.1.110",
            "Info": "428892,428892,76"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-07-01T20:06:41Z",
            "Log Type": "System Call",
            "Potential Severity": "HIGH",
            "Lead": "Many processes got opened on IP 192.168.1.110 by process with PID 428892",
            "Info": "Over 20 processes got opened by PID 428892 in the last 5 minutes.\n"
            "It seems like some process is trying to perform some malicious actions.\n"
            "Consider investigating the source IP and PID in order to avoid security risks.\n"
            "To kill the source PID, use the following command: `sudo kill -9 PID`"
          }
        ])
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in ebpf_info)
      }
    ]
  )

  return (completion.choices[0].message.content)
  

# Main function in order to be able to send data without the API from the agent.
def main():
  system_calls = []
  severity_field = "Potential Severity"

# Append events stored on MongoDB
  cursor = collection.find({})
  for document in cursor:
    system_calls.append(document)

  if system_calls:
    print("Starting to analyze your data...")

    potential_threats = generate_insights(system_calls)

    potential_threats = [ast.literal_eval(potential_threats)]

    print("Printing insights results...")
    for syscall in potential_threats:
      if 'Severity' in syscall:
          severity_field = 'Severity'
      elif 'Potential Severity' in syscall:
          severity_field = 'Potential Severity'
     
      severity = syscall[severity_field].lower()
      match severity:
          case "neutral":
              logger.info(syscall)
              print(syscall)
          case "low":
              logger.info(syscall)
              print(syscall)
          case "medium":
              logger.warning(syscall)
              print(syscall)
          case "high":
              logger.error(syscall)
              print(syscall)
          case "critical":
              logger.error(syscall)
              print(syscall)
          case _:
              logger.info(syscall)
              print(syscall)

    
if __name__ == "__main__":
  main()
