from cryptography.fernet import Fernet
import os
import base64
import hashlib
import uuid

class FileClient:
    def __init__(self, user_id):
        self.user_id = user_id
        self.key = self._load_or_create_key()
        self.cipher_suite = Fernet(self.key)
    
    def _load_or_create_key(self):
        # Use application-wide fixed key
        fixed_key = os.getenv('ENCRYPTION_KEY', 'your-very-secret-key-32bytes').encode()
        # Ensure key is exactly 32 bytes URL-safe base64
        return base64.urlsafe_b64encode(fixed_key.ljust(32)[:32])
    
    def encrypt_file(self, filepath):
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Encrypt content
        encrypted_content = self.cipher_suite.encrypt(file_content)
        
        # Generate unique file ID
        file_id = str(uuid.uuid4())
        
        # Save encrypted file
        encrypted_filename = f"encrypted_{file_id}.bin"
        encrypted_path = os.path.join('encrypted_files', encrypted_filename)
        
        os.makedirs('encrypted_files', exist_ok=True)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_content)
        
        return file_id, encrypted_path
    
    def decrypt_file(self, encrypted_path, output_path):
        # Read encrypted content
        with open(encrypted_path, 'rb') as f:
            encrypted_content = f.read()
        
        # Decrypt content
        try:
            decrypted_content = self.cipher_suite.decrypt(encrypted_content)
        except:
            raise ValueError("Decryption failed - possibly wrong key or corrupted file")
        
        # Save decrypted file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(decrypted_content)
        
        return output_path