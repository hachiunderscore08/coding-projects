from flask import Flask, request, jsonify
from file_client import FileClient

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    file_data = request.files['file']
    user_id = "test_user"  # Simulate user ID (actually obtained from JWT)
    client = FileClient(user_id)
    file_id, encrypted_path = client.encrypt_file(file_data.filename)
    return jsonify({"status": "success", "file_id": file_id})

if __name__ == "__main__":
    app.run(port=5000)  # Start Flask service