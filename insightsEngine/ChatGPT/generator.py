# Imports
import json
from pymongo import MongoClient
from datetime import datetime, timedelta
from openai import OpenAI

# Global Variables 
minute_timedelta = (datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
aggregate_pipeline = [
    {
        "$match": {
            "Time": {
                "$gt": minute_timedelta
            }
        }
    },
    {
        "$facet": {
            "countOne": [
                { "$match": { "Count": '1' } }
            ],
            "maxCounts": [
                { "$match": { "Count": { "$ne": '1' } } },
                {
                    "$group": {
                        "_id": "$Type",
                        "maxCount": { "$max": "$Count" },
                        "doc": { "$first": "$$ROOT" }
                    }
                },
                {
                    "$replaceRoot": { "newRoot": "$doc" }
                }
            ]
        }
    },
    {
        "$project": {
            "result": { "$concatArrays": ["$countOne", "$maxCounts"] }
        }
    },
    { "$unwind": "$result" },
    { "$replaceRoot": { "newRoot": "$result" } }
]


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
        "content": "For each list of JSONs: \n1.Print logs with suspicious methods indicating potential security threats."
        "\n2. Use this header:\nid: 'id',\nSeverity: NEUTRAL/LOW/MEDIUM/HIGH/CRITICAL,"
        "\nAction_Items: 'action_items'.\n- Severity: Based on inferred threat level."
        "\n- Action_Items: suggest immediate actions to address the potential threat."
        "\n3. Group similar logs from different hosts if they indicate a widespread issue or repeat on the same host."
        "\n4. Censor passwords in the output."
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "id": "6696d34a2e0e2aa954764a58",
            "info": "User IdanDo with UID 1234 successfully logged-in via SSH from 192.168.1.105"
          },
          {
             "id": "6696v34a2e4e2aa984764a58",
            "info": "User IdanDo with UID 1234 successfully logged-in via SSH from 192.168.1.105"
          },
          {
            "id": "f696d34a2e0e2aa954764a56",
            "info": "PID 2004 forked 54 subprocesses"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "id": ["6696d34a2e0e2aa954764a58", "6696v34a2e4e2aa984764a58"],
            "Severity": "MEDIUM",
            "Action_Items": ["Consider blocking the source IP by running the following command: `sudo iptables -A INPUT -s 192.168.1.105 -j DROP`.\n"
            "Consider changing the user password by running the following command: `sudo passwd IdanDo <password>`"]
          },
          {
            "id": ["f696d34a2e0e2aa954764a56"],
            "Severity": "HIGH",
            "Action_Items": ["Kill PID by running the following command: `kill -9 PID`.\n"
            "Consider investigating the source PID and restrict the PID to avoid future attacks."]  
          }
        ])
      },
      {
        "role": "user",
        "content": ",".join(str(element) for element in [
          {
            "id": "f696d6va2e0e2ac954764a56",
            "info": "User DoronKG with UID 5674 created file /etc/malicious"
          },
          {
            "id": "f696d6ba2e0e2ac944769a56",
            "info": "Host 192.168.1.106 scanned 2048 ports"
          }
        ])
      },
      {
        "role": "assistant",
        "content": ",".join(str(element) for element in [
          {
            "id": ["f696d6va2e0e2ac954764a56"],
            "Severity": "CRITICAL",
            "Action_Items": ["Verify that user DoronKG has the right permissions to create a file under /etc.\n"
            "Consider investigating the file and changing it's ACL by running the following command: `sudo setfacl <owner>:<permissions> /etc/malicious`."]
          },
          {
            "id": ["f696d6ba2e0e2ac944769a56"],
            "Severity": "LOW",
            "Action_Items": ["Consider blocking the source IP by running the follwoing command: `sudo iptables -A INPUT -s 192.168.1.106 -j DROP`.\n"
            "Verify that only relevant ports are open by running the following command: `sudo netstat -tupln`."]  
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
  documents = []
  logger = configure_logger()
  
  cursor = collection.aggregate(aggregate_pipeline)
  for document in cursor:
     documents.append(document)
     log_obj = {
            "info": document["Info"],
            "id": str(document["_id"])}
     system_calls.append(log_obj)

  if system_calls:
    print("Starting to analyze your data...")

    potential_threats = generate_insights(system_calls)

    print("Printing insights results...")

        # Validate that each threat returned by the model has the required fields for error handling
    ids = []
    info_list = []

    for threat in potential_threats:
      valid_id = threat.get("id")
      valid_severity = threat.get("Severity")
      valid_action_item = threat.get("Action_Items")    

      if not all([valid_id, valid_severity, valid_action_item]):
              continue

      for id in threat.get("id"):
          for doc in documents:
             if (id == str(doc.get("_id")) and doc.get("Target") == threat.get("Target")):
                ids.append(id)
                info_list.append(doc.get("Info"))
                break
    
    log_obj = {
                "id": ids,
                "Time": doc.get("Time"),
                "Log_Type": "systemcall",
                "Severity": threat.get("Severity"),
                "Targets": doc.get("Target"),
                "Info": info_list,
                "Action_Items": threat.get("Action_Items")
              }
    
    print(json.dumps(log_obj))
    logger.warning(json.dumps(log_obj))

if __name__ == "__main__":
  main()
