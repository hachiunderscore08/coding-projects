import uuid
from passlib.hash import argon2
import sqlite3
from mfa import MFAManager
import os

class AuthManager:
    def __init__(self):
        self.conn = sqlite3.connect('secure_storage.db')
    
    def register(self, username, password):
        # Check if the username is unique
        cursor = self.conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            return False
        
        # Hashing passwords
        password_hash = argon2.hash(password)
        
        # Storing users
        cursor.execute(
            "INSERT INTO users (user_id, username, password_hash, mfa_enabled) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), username, password_hash, False)
        )
        self.conn.commit()
        return True
    
    def login(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT user_id, password_hash, mfa_enabled FROM users WHERE username=?",
            (username,)
        )
        user = cursor.fetchone()
        if user and argon2.verify(password, user[1]):
            if user[2]:  # MFA is enabled
                return {"status": "mfa_required", "user_id": user[0]}
            return {"status": "success", "user_id": user[0]}
        return {"status": "failed"}
    
    def reset_password(self, username, old_password, new_password):
        """Reset Password"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT password_hash FROM users WHERE username=?", (username,)
        )
        user = cursor.fetchone()
        if user and argon2.verify(old_password, user[0]):
            new_hash = argon2.hash(new_password)
            cursor.execute(
                "UPDATE users SET password_hash=? WHERE username=?",
                (new_hash, username)
            )
            self.conn.commit()
            return True
        return False

    def enable_mfa(self, username):
        """Enable MFA for a user and return both secret and QR code path"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if not user:
            return None, None
        
        mfa = MFAManager(user[0])
        provisioning_uri = mfa.get_provisioning_uri(username)
        
        # Generate QR code path
        qr_code_path = f"mfa_qrcodes/{username}_mfa_qr.png"
        os.makedirs("mfa_qrcodes", exist_ok=True)
        
        
        # Update the database
        cursor.execute(
            "UPDATE users SET mfa_enabled=?, mfa_secret=? WHERE username=?",
            (True, mfa.secret, username)
        )
        self.conn.commit()
        
        # Save the secret to a file
        with open('qr_code.txt', 'w') as f:
            f.write(f"Secret: {mfa.secret}\n")
            f.write(f"QR Code saved to: {qr_code_path}\n")
        
        return mfa.secret, qr_code_path  # Return two values

    def disable_mfa(self, username, code):
        """Disable MFA for a user after verifying the current code"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT user_id, mfa_secret FROM users WHERE username=? AND mfa_enabled=?",
            (username, True)
        )
        user = cursor.fetchone()
        if not user:
            return False
        
        mfa = MFAManager(user[0])
        mfa.secret = user[1]
        
        if mfa.verify_totp(code):
            cursor.execute(
                "UPDATE users SET mfa_enabled=?, mfa_secret=? WHERE username=?",
                (False, None, username)
            )
            self.conn.commit()
            return True
        return False

    def verify_mfa(self, username, code):
        """Verify MFA code for a user"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT user_id, mfa_secret FROM users WHERE username=? AND mfa_enabled=?",
            (username, True)
        )
        user = cursor.fetchone()
        if not user:
            return False
        
        mfa = MFAManager(user[0])
        mfa.secret = user[1]
        return mfa.verify_totp(code)

    def is_mfa_enabled(self, username):
        """Check if MFA is enabled for a user"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT mfa_enabled FROM users WHERE username=?",
            (username,)
        )
        result = cursor.fetchone()
        return bool(result and result[0])