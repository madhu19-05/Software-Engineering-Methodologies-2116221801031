import os
import subprocess
import uuid
import shutil
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='static')
CORS(app)

# Configure upload folder
UPLOAD_FOLDER = './tmp'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Store decrypted file information
decrypted_files = {}

def clear_tmp_folder():
    for filename in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output.decode('utf-8'), error.decode('utf-8'), process.returncode

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/generate-key', methods=['POST'])
def generate_key():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    
    key_params = f"""
    Key-Type: RSA
    Key-Length: 4096
    Name-Real: {name}
    Name-Email: {email}
    Expire-Date: 0
    %commit
    """
    
    with open('/tmp/key_params', 'w') as f:
        f.write(key_params)
    
    cmd = "gpg --batch --generate-key /tmp/key_params"
    output, error, rc = run_command(cmd)
    
    if rc == 0:
        return jsonify({"message": "Key pair generated successfully."})
    else:
        return jsonify({"error": f"Error generating key pair: {error}"}), 400

@app.route('/encrypt-and-sign', methods=['POST'])
def encrypt_and_sign():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    recipient_email = request.form.get('recipientEmail')
    sender_email = request.form.get('senderEmail')
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file and recipient_email and sender_email:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Encrypt the file
        encrypt_cmd = f"gpg --output {filepath}.gpg --encrypt --recipient {recipient_email} {filepath}"
        _, error, rc = run_command(encrypt_cmd)
        if rc != 0:
            if "Connection refused" in error:
                return jsonify({"error": "Encryption failed: Unable to retrieve the recipient's public key. Please ensure the key is available and try again."}), 400
            else:
                return jsonify({"error": f"Encryption failed: {error}"}), 400
        
        # Sign the encrypted file
        sign_cmd = f"gpg --output {filepath}.sig --detach-sign --local-user {sender_email} {filepath}.gpg"
        _, error, rc = run_command(sign_cmd)
        if rc != 0:
            return jsonify({"error": f"Signing failed: {error}"}), 400
        
        return jsonify({"message": "File encrypted and signed successfully."})
    
    return jsonify({"error": "Missing required parameters"}), 400

@app.route('/decrypt-and-verify', methods=['POST'])
def decrypt_and_verify():
    if 'encryptedFile' not in request.files or 'signatureFile' not in request.files:
        return jsonify({"error": "Missing required files"}), 400
    
    encrypted_file = request.files['encryptedFile']
    signature_file = request.files['signatureFile']
    verification_email = request.form.get('verificationEmail')
    
    if encrypted_file.filename == '' or signature_file.filename == '':
        return jsonify({"error": "No selected files"}), 400
    
    if encrypted_file and signature_file and verification_email:
        encrypted_filename = secure_filename(encrypted_file.filename)
        signature_filename = secure_filename(signature_file.filename)
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        signature_filepath = os.path.join(app.config['UPLOAD_FOLDER'], signature_filename)
        encrypted_file.save(encrypted_filepath)
        signature_file.save(signature_filepath)
        
        # Verify the signature
        verify_cmd = f"gpg --verify {signature_filepath} {encrypted_filepath}"
        _, error, rc = run_command(verify_cmd)
        if rc != 0:
            return jsonify({"error": f"Signature verification failed: {error}"}), 400
        
        # Decrypt the file
        decrypted_filepath = encrypted_filepath[:-4]  # Remove .gpg extension
        decrypt_cmd = f"gpg --output {decrypted_filepath} --decrypt {encrypted_filepath}"
        _, error, rc = run_command(decrypt_cmd)
        if rc != 0:
            return jsonify({"error": f"Decryption failed: {error}"}), 400
        
        # Generate a unique ID for the decrypted file
        file_id = str(uuid.uuid4())
        decrypted_files[file_id] = {
            'path': decrypted_filepath,
            'name': os.path.basename(decrypted_filepath)
        }
        
        return jsonify({
            "message": "File decrypted and signature verified successfully.",
            "fileId": file_id
        })
    
    return jsonify({"error": "Missing required parameters"}), 400

@app.route('/download-file/<file_id>')
def download_file(file_id):
    if file_id not in decrypted_files:
        return "File not found", 404
    
    file_info = decrypted_files[file_id]
    return send_file(file_info['path'], as_attachment=True, download_name=file_info['name'])

if __name__ == '__main__':
    clear_tmp_folder()  # Clear the tmp folder before starting the application
    app.run(debug=True)
