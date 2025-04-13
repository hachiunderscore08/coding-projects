import os
import sqlite3
import uuid
from auth import AuthManager
from mfa import MFAManager
import pyotp
import time
from cryptography.fernet import Fernet
import logging
from datetime import datetime

def setup_logging():
    """Set up logging system"""
    logging.basicConfig(
        filename='app.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def test_user_management():
    """Test user management functionality"""
    print("\n=== Testing User Management ===")
    auth = AuthManager()
    
    # 1. Test user registration
    print("\n1. Testing User Registration...")
    username = f"test_user_{int(time.time())}"
    password = "Test123!"
    
    # Test unique username
    print("Testing unique username registration:")
    result = auth.register(username, password)
    print(f"First registration result: {result}")
    result = auth.register(username, password)
    print(f"Duplicate registration result: {result}")
    
    # 2. Test login
    print("\n2. Testing Login...")
    # Test correct password
    print("Testing login with correct password:")
    login_result = auth.login(username, password)
    print(f"Login result: {login_result}")
    
    # Test incorrect password
    print("Testing login with incorrect password:")
    login_result = auth.login(username, "WrongPass!")
    print(f"Login result: {login_result}")
    
    # 3. Test password reset
    print("\n3. Testing Password Reset...")
    new_password = "NewTest123!"
    
    # Test with incorrect old password
    print("Testing reset with incorrect old password:")
    reset_result = auth.reset_password(username, "WrongPass!", new_password)
    print(f"Reset result: {reset_result}")
    
    # Test with correct old password
    print("Testing reset with correct old password:")
    reset_result = auth.reset_password(username, password, new_password)
    print(f"Reset result: {reset_result}")

def test_data_encryption():
    """Test data encryption functionality"""
    print("\n=== Testing Data Encryption ===")
    
    # Generate encryption key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    
    # Test file encryption
    print("\n1. Testing File Encryption...")
    test_data = b"Test file content for encryption"
    encrypted_data = cipher_suite.encrypt(test_data)
    print(f"Before encryption: {test_data}")
    print(f"After encryption: {encrypted_data}")
    
    # Test file decryption
    print("\n2. Testing File Decryption...")
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    print(f"After decryption: {decrypted_data}")
    print(f"Decryption match: {decrypted_data == test_data}")

def test_access_control():
    """Test access control functionality"""
    print("\n=== Testing Access Control ===")
    
    # Create test users
    auth = AuthManager()
    user1 = f"test_user1_{int(time.time())}"
    user2 = f"test_user2_{int(time.time())}"
    password = "Test123!"
    
    auth.register(user1, password)
    auth.register(user2, password)
    
    # Test file ownership
    print("\n1. Testing File Ownership...")
    file_id = str(uuid.uuid4())
    owner_id = auth.login(user1, password)["user_id"]
    
    # Simulate file storage
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            owner_id TEXT,
            filename TEXT,
            content BLOB,
            shared_with TEXT
        )
    """)
    
    # Test file upload
    print("Testing file upload:")
    cursor.execute(
        "INSERT INTO files (file_id, owner_id, filename, content) VALUES (?, ?, ?, ?)",
        (file_id, owner_id, "test.txt", b"test content")
    )
    conn.commit()
    
    # Test file access permissions
    print("\n2. Testing File Access Permissions...")
    cursor.execute(
        "SELECT * FROM files WHERE file_id=? AND owner_id=?",
        (file_id, owner_id)
    )
    result = cursor.fetchone()
    print(f"Owner access to file: {result is not None}")
    
    cursor.execute(
        "SELECT * FROM files WHERE file_id=? AND owner_id=?",
        (file_id, "wrong_owner")
    )
    result = cursor.fetchone()
    print(f"Non-owner access to file: {result is None}")
    
    # Test file sharing
    print("\n3. Testing File Sharing...")
    shared_user_id = auth.login(user2, password)["user_id"]
    cursor.execute(
        "UPDATE files SET shared_with=? WHERE file_id=?",
        (shared_user_id, file_id)
    )
    conn.commit()
    
    cursor.execute(
        "SELECT * FROM files WHERE file_id=? AND (owner_id=? OR shared_with=?)",
        (file_id, shared_user_id, shared_user_id)
    )
    result = cursor.fetchone()
    print(f"Shared user access to file: {result is not None}")
    
    conn.close()

def test_logging_audit():
    """Test logging and audit functionality"""
    print("\n=== Testing Logging and Audit ===")
    setup_logging()
    
    # Test log recording
    print("\n1. Testing Operation Logging...")
    test_actions = [
        ("login", "user123"),
        ("upload", "file1.txt"),
        ("delete", "file2.txt"),
        ("share", "file3.txt")
    ]
    
    for action, target in test_actions:
        logging.info(f"User performed {action} on {target}")
        print(f"Recording {action} operation")
    
    # Test log reading
    print("\n2. Testing Log Reading...")
    with open('app.log', 'r') as f:
        logs = f.readlines()
        print("Recent log entries:")
        for log in logs[-4:]:
            print(log.strip())

def test_security_protections():
    """Test security protection features"""
    print("\n=== Testing Security Protections ===")
    
    # Test filename validation
    print("\n1. Testing Filename Validation...")
    dangerous_filenames = [
        "../file.txt",
        "../../etc/passwd",
        "file; rm -rf /",
        "file' OR '1'='1"
    ]
    
    for filename in dangerous_filenames:
        # Simple filename sanitization
        safe_filename = os.path.basename(filename)
        print(f"Dangerous filename: {filename}")
        print(f"Safe filename: {safe_filename}")
    
    # Test SQL injection protection
    print("\n2. Testing SQL Injection Protection...")
    auth = AuthManager()
    username = f"test_user_sql_{int(time.time())}"
    password = "Test123!"
    
    # Use parameterized queries
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()
    
    # Test SQL injection attempts
    print("Testing SQL injection attempts:")
    injection_attempts = [
        "admin' --",
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users; --"
    ]
    
    for attempt in injection_attempts:
        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (attempt,)
        )
        result = cursor.fetchone()
        print(f"SQL injection attempt '{attempt}': {'Failed' if result is None else 'Succeeded'}")
    
    conn.close()

def test_mfa():
    """Test Multi-Factor Authentication functionality"""
    print("\n=== Testing Multi-Factor Authentication ===")
    auth = AuthManager()
    username = f"test_user_{int(time.time())}"
    password = "Test123!"
    
    # Register user
    auth.register(username, password)
    
    # Test MFA enable
    print("\n1. Testing MFA Enable...")
    secret = auth.enable_mfa(username)
    print(f"MFA Secret: {secret}")
    
    # Test MFA verification
    print("\n2. Testing MFA Verification...")
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    
    # Test correct verification code
    print("Testing correct verification code:")
    verify_result = auth.verify_mfa(username, current_code)
    print(f"Verification result: {verify_result}")
    
    # Test incorrect verification code
    print("Testing incorrect verification code:")
    verify_result = auth.verify_mfa(username, "000000")
    print(f"Verification result: {verify_result}")
    
    # Test MFA disable
    print("\n3. Testing MFA Disable...")
    current_code = totp.now()
    disable_result = auth.disable_mfa(username, current_code)
    print(f"Disable result: {disable_result}")

def main():
    """Run all tests"""
    print("Starting comprehensive tests...")
    
    # Run core functionality tests
    test_user_management()
    test_data_encryption()
    test_access_control()
    test_logging_audit()
    test_security_protections()
    
    # Run extended functionality tests
    test_mfa()
    
    print("\nTests completed!")

if __name__ == "__main__":
    main() 