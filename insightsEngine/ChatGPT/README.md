# Insights Engine

## Overview

The insightsEngine script is built with a function that interacts with ChatGPT API in order to gather insights from eBPF metrics collected from agent.
The insightsEngine will print the insights in colors according to the severity detected.

## Prerequisites

1. Create a local virtual environment using the following commands:
```
$ python3 -m venv .venv
$ source ~/.venv/bin/activate
```
2. Install all python packages written in requirements.txt file using the follwoign command: `pip3 install -r requirements.txt`.
3. Export the environment variable OPENAI_API_KEY and put ChatGPT API key inside with the following command: `export OPENAI_API_KEY=<content>`.
4. Change the permissions on the generator file to be executable, with `chmod +x generator.py`.
5. If you run only the generator without the agent, make sure that the sample metrics file is inside the agent directory.

## Execution
 In order to execute the generator, please run the following command: `python3 generator.py`.
 The generator will read the contents of the csv file and will send to ChatGPT for generation of insights.

## Generator Output

The generator code has 2 options of outputs:
1. Concrete output with action items in order to avoid and prevent security risks.
   The output looks like the following:
    timestamp: {{ 2024-04-15T12:45:23Z }}
    type: {{ syscall }}
    hostname: {{ 192.168.1.101 }}
    severity: {{ high }}
    info: {{ User 501 called 'execve' on '/usr/local/bin/suspicious_script.sh', potentially harmful behavior detected. }}
    action items: 1. ...

2. A lead of optential threat. The output looks like the followiing:
    timestamp: {{ 2024-04-15T12:50:00Z }}
    type: {{ security alert }}
    potential severity: {{ critical }}
    lead: {{ Multiple failed login attempts detected from IP 192.168.1.105 }}
    information: {{ Over 20 failed login attempts in the last 5 minutes. Consider investigating the source IP and applying IP-based blocking or rate limiting. To block this IP using iptables, use the following command: 'sudo iptables -A INPUT -s 192.168.1.105 -j DROP' }}
