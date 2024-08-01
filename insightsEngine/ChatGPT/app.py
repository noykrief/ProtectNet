from flask import Flask, request, jsonify
from insightsEngine.ChatGPT.generator import test_insight
from pymongo import MongoClient

import requests
import json

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
        insight_info = request.get_json()
        log_time = insight_info['time']
        log_type = insight_info['log_type']
        target = insight_info['target']
        
        if (test_insight(log_type, target)):
            headers = {'Content-Type': 'application/json'}
            query = '{logger="LokiLogger"}' + f"|= `{target}` | json | Log_Type = `{log_type}` | Time = `{log_time}`"

            requests.post("http://10.10.248.155:3100/loki/api/v1/delete", headers=headers, data=json.dumps(query))
            return jsonify({"message": "Loki data deleted successfully"}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True, port=5000)
