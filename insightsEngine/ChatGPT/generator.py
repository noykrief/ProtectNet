import json
from pymongo import MongoClient
from datetime import datetime, timedelta

from openai import OpenAI

def configure_logger():
  import logging
  import logging_loki
  # Setup Loki configurations in order to send logs        
  logging_loki.emitter.LokiEmitter.level_tag = "level"

  handler = logging_loki.LokiHandler(
          url="http://10.10.248.155:3100/loki/api/v1/push",
          version="1",
          )
  logger = logging.getLogger("LokiLogger")
  logger.addHandler(handler)

  return logger

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
        "from streaming data relating system calls, network and kernel, collected through eBPF.",
      },
      {
        "role": "system",
        "content": "For each list of JSONs: \n1. Print logs with suspicious methods indicating potential security threats."
        "\n2. Use this header:\nTime: 'timestamp',\nLog_Type: 'log_type',\nTargets: 'targets',"
        "\nSeverity: NEUTRAL/LOW/MEDIUM/HIGH/CRITICAL,"
        "\nLead: 'lead',\nInfo: 'information',\nAction_Items: 'action_items'.\n- Severity: Based on inferred threat level."
        "\n- Lead: Explain the gathered logs.\n- Info: Detailed threat information."
        "\n- Action_Items: suggest immediate actions to address the potential threat."
        "\n3. Group similar logs from different hosts if they indicate a widespread issue or repeat on the same host."
        "\n4. Censor passwords in the output."
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:50:00",
            "Log Type": "System Call",
            "Target": "192.168.1.105",
            "Info": "Failed SSH connection from PID 1234"
          },
          {
            "Time": "2024-04-15T12:50:26",
            "Log Type": "System Call",
            "Target": "192.168.1.105",
            "Info": "Failed SSH connection from PID 1234"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:51:00",
            "Log_Type": "System Call",
            "Targets": ["192.168.1.105"],
            "Severity": "MEDIUM",
            "Lead": "Multiple login attempts detected from IP 192.168.1.105",
            "Info": "The host is vulnerable to DOS attack / port scan on port 22",
            "Action_Items": ["Consider investigation the source IP and applying IP-based blocking or rate limiting.\n"
            "To block this IP using iptables, use the following command: `sudo iptables -A INPUT -s 192.168.1.105 -j DROP`"]
          }
        ])
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:47:15",
            "Log Type": "System Call",
            "Target": "192.168.1.102",
            "Info": "502, open, /etc/shadow"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "Time": "2024-04-15T12:47:15",
            "Log_Type": "System Call",
            "Targets": ["192.168.1.102"],
            "Severity": "NEUTRAL",
            "Lead": "PID 502 attempted to open a sensitive file",
            "Info": "Sensitive data could be exposed",
            "Action_Items": ["Manage ACL on the sensitive file", "Kill suspicious PID 502 using `sudo kill -p PID`"]
          }
        ])
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in ebpf_info)
      }
    ]
  )

  return [json.loads(completion.choices[0].message.content)]
  

def test_insight(log_type, target):
  system_calls = []

  # Append events stored on MongoDB
  minute_timedelta = (datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
  cursor = collection.find({ "Time": { "$gt": f"{minute_timedelta}" } })
  for document in cursor:
    if log_type == document['Type'] and target == document['Target']:
       return False
  return True

# Main function in order to be able to send data without the API from the agent.
def main():
  system_calls = []

  logger = configure_logger()

# Append events stored on MongoDB
  minute_timedelta = (datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
  cursor = collection.find({ "Time": { "$gt": f"{minute_timedelta}" } })
  for document in cursor:
    system_calls.append(document)

  if system_calls:
    print("Starting to analyze your data...")

    potential_threats = generate_insights(system_calls)

    print("Printing insights results...")
    for syscall in potential_threats:
     
      severity = syscall["Severity"].lower()
      syscall = json.dumps(syscall)
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
