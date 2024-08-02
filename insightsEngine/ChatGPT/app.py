from flask import Flask, request, jsonify
from generator import test_insight
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone

import requests
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
        
        if (test_insight(log_type, target)):

            log_time =  datetime.strftime(log_time, "%Y-%m-%dT%H:%M:%SZ")
            start_time = log_time - timedelta(seconds=30)

            print(start_time, log_time)
            params = {
                'query': '{logger="LokiLogger"}' + f'|= `{target}` | json | Log_Type = `{log_type}` | Time = `{log_time}`',
                'start': start_time,
                'end': log_time
            }

            headers = {'Content-Type': 'application/x-www-form-urlencoded'}

            result = requests.post("http://10.10.248.155:3100/loki/api/v1/delete", headers=headers, params=params)
            print(result.content)
            return jsonify({"message": "Loki data deleted successfully"}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True, port=5000)
