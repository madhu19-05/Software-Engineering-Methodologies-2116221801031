from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# Initialize Flask app
app = Flask(__name__)

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json.get('data')
    if data is None:
        return jsonify({'error': 'No data provided. Please provide data for encryption.'}), 400
    try:
        encrypted_data = cipher_suite.encrypt(data.encode())
        return jsonify({'ciphertext': encrypted_data.decode()}), 200
    except Exception as e:
        return jsonify({'error': f'Error encrypting data: {str(e)}'}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_data = request.json.get('ciphertext')
    if encrypted_data is None:
        return jsonify({'error': 'No ciphertext provided. Please provide ciphertext for decryption.'}), 400
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
        return jsonify({'data': decrypted_data}), 200
    except Exception as e:
        return jsonify({'error': f'Error decrypting data: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
