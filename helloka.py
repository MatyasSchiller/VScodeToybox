#pip install flask

import numpy as np 
from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

# Example data
domains = {
    'example.com': '127.0.0.1',
    'example.net': '192.168.1.2'
}

users = {
    'user1': hashlib.sha256('password1'.encode()).hexdigest(),
    'user2': hashlib.sha256('password2'.encode()).hexdigest()
}

def authenticate(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return users.get(username) == hashed_password

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if authenticate(username, password):
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"message": "Login failed"}), 401

@app.route('/domain/<domain_name>', methods=['GET'])
def get_domain(domain_name):
    ip_address = domains.get(domain_name)
    if ip_address:
        return jsonify({"domain": domain_name, "ip": ip_address}), 200
    else:
        return jsonify({"message": "Domain not found"}), 404

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)