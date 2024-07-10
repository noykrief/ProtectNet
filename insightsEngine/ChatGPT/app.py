from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB configuration
client = MongoClient('mongodb://localhost:27717/')
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
