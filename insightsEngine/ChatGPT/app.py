from flask import Flask, request, jsonify
from generator import test_insight, configure_logger
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone

import requests
import json
import time

app = Flask(__name__)

# MongoDB configuration
client = MongoClient('mongodb://10.10.248.155:27717/')
db = client['agents_metrics']
collection = db['metrics']

@app.route('/data', methods=['POST'])
def receive_data():
    try:
        json_data = request.get_json()
        result = collection.insert_one(json_data)

        return jsonify({"message": "Data inserted successfully", "id": str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

@app.route('/test', methods=['GET'])
def test_event():
    try:
        log_time = request.args.get('time')
        log_type = request.args.get('log_type')
        target = request.args.get('target')
        logger = configure_logger()
        
        if (test_insight(log_type, target)):

            utc_log_time =  datetime.strptime(log_time, "%Y-%m-%dT%H:%M:%S").astimezone(timezone.utc)
            start_time = (utc_log_time - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
            end_time = utc_log_time.isoformat().replace("+00:00", "Z")

            params = {
                'query': '{logger="LokiLogger"}' + f'|= `{target}` | json | Log_Type = `{log_type}` | Time = `{log_time}`',
                'start': start_time,
                'end': end_time
            }

            # query_params = {
            #     'query': '{logger="LokiLogger"}' + f'|= `{target}` | json | Log_Type = `{log_type}` | Time = `{log_time}`',
            #     'start': start_time
            # }

            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            # result = requests.get("http://10.10.248.155:3100/loki/api/v1/query_range", headers=headers, params=query_params)

            # resolved = json.loads(result.json()['data']['result'][0]['values'][0][1])
            # resolved['Severity'] = 'Resolved'
            
            # print(resolved)

            # logger.warn(json.dumps(resolved))            
            result = requests.post("http://10.10.248.155:3100/loki/api/v1/delete", headers=headers, params=params)
            print(result.content)
            return jsonify({"message": "Loki deleted log successfully"}), 201
        return jsonify({"message": "Event is still relevant"}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True, port=5000)
