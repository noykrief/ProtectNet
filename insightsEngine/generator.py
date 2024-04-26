# This will be the file where the chatGPT integrstion will happen and all functionswill be written here

import os
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
        "content": "Time: 2024-04-15T12:45:23Z\nType: System Call\nHost: 192.168.1.101\n"
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
    ]
  )
