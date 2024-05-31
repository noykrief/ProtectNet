import os
import csv
import ast

from openai import OpenAI
from dotenv import load_dotenv
from colorama import Fore


# Load environemnt variables for interacting with ChatGPT
load_dotenv()
OPENAI_API_KEY=os.getenv("OEPNAI_API_KEY")
        
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
        "content": ",".join(str(element) for element in ebpf_info)
      }
    ]
  )

  return (completion.choices[0].message.content)
  

# POC Part - main function in order to be able to send data without the API from the agent.
def main():
  system_calls = []

  severity_colors = {
    "NEUTRAL": Fore.GREEN,
    "LOW": Fore.WHITE,
    "MEDIUM": Fore.YELLOW,
    "HIGH": Fore.RED,
    "CRITICAL": Fore.LIGHTRED_EX
  }

  # file to open after running the agent and saving data to a file for POC
  with open(f"agent/metrics-{os.getenv('TS')}.csv", newline="") as csvfile:
    csv_reader = csv.DictReader(csvfile)
    for row in csv_reader:
      system_calls.append(row)

  if system_calls:
    print("Starting to analyze your data...")

    potential_threats = generate_insights(system_calls)

    potential_threats = [ast.literal_eval(potential_threats)]

    print("Printing insights results...")
    for syscall in potential_threats:
      for severity, color in severity_colors.items():
        if severity.lower() == syscall['Severity'].lower() or severity.lower() == syscall['Potential Severity'].lower():
          print(color, syscall)
          break
    
if __name__ == "__main__":
  main()