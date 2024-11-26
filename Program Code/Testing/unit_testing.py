import unittest
import json
from app import app  # Import the Flask app for testing

class AdvancedTests(unittest.TestCase):
    """Test encryption/decryption cases."""

    def setUp(self):
        """Set up the test client."""
        self.client = app.test_client()
        self.client.testing = True

    def test_encrypt_decrypt_string(self):
        """Test encrypting and decrypting a simple string."""
        data = {'data': 'hello'}
        response = self.client.post('/encrypt', json=data)
        self.assertEqual(response.status_code, 200)  # Check if the response is 200
        encrypted_data = json.loads(response.data).get('ciphertext')
        self.assertIsInstance(encrypted_data, str)
        self.assertNotEqual(encrypted_data, '')  # Check if it's not empty
        response = self.client.post('/decrypt', json={'ciphertext': encrypted_data})
        self.assertEqual(response.status_code, 200)
        decrypted_data = json.loads(response.data).get('data')
        self.assertEqual(decrypted_data, 'hello')  # Verify if the decrypted data matches

    def test_edge_case_empty_string(self):
        """Test encrypting and decrypting an empty string."""
        data = {'data': ''}
        response = self.client.post('/encrypt', json=data)
        self.assertEqual(response.status_code, 200)  # Check if encryption is successful
        encrypted_data = json.loads(response.data).get('ciphertext')
        self.assertIsInstance(encrypted_data, str)
        self.assertNotEqual(encrypted_data, '')  # Ensure encrypted data is not empty
        response = self.client.post('/decrypt', json={'ciphertext': encrypted_data})
        self.assertEqual(response.status_code, 200)
        decrypted_data = json.loads(response.data).get('data')
        self.assertEqual(decrypted_data, '')  # Verify if it's an empty string

    def test_invalid_encryption_request(self):
        """Test sending invalid encryption request."""
        data = {'wrong_key': 'data'}  # Missing 'data' key
        response = self.client.post('/encrypt', json=data)
        self.assertEqual(response.status_code, 400)  # Check if it's handled as a bad request

if __name__ == '__main__':
    unittest.main()
