# from flask import Flask, request
# from ChatGPT.generator import generate_insights

# app = Flask(__name__)

# @app.route('/generate', methods=['POST'])
# def ebpf_to_chat():
#     data = request.json
#     generate_insights(data)
#     return 'Data sent successfully', 200

# if __name__ == '__main__':
#     app.run(debug=True)