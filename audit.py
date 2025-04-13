import sqlite3
import uuid
from io import StringIO
import os
from mfa import MFAManager

class AuditLogger:
    def __init__(self):
        self.conn = sqlite3.connect('secure_storage.db', check_same_thread=False)
        self._init_db()
    
    def _init_db(self):
        cursor = self.conn.cursor()
        
        # 更简单的CREATE TABLE语句，避免多行字符串可能的问题
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT,
            target TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Add a foreign key constraint separately
        try:
            cursor.execute("""
            ALTER TABLE audit_logs 
            ADD CONSTRAINT fk_user_id
            FOREIGN KEY (user_id) REFERENCES users(user_id)
            """)
        except sqlite3.OperationalError:
            # If the foreign key already exists or the users table does not exist, ignore the error
            pass
            
        self.conn.commit()
    
    def log_action(self, user_id, action, target):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO audit_logs (log_id, user_id, action, target) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), user_id, action, str(target))
            )
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Error logging action: {e}")
    
    def get_logs(self, user_id=None, limit=50):
        try:
            cursor = self.conn.cursor()
            if user_id:
                cursor.execute(
                    "SELECT * FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                    (user_id, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error retrieving logs: {e}")
            return []
    
    def __del__(self):
        try:
            self.conn.close()
        except:
            pass

    def enable_mfa(self, username):
        """Enable MFA for a user and return both secret and QR code path"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if not user:
            return None, None  # Return tuple of Nones if user not found
        
        mfa = MFAManager(user[0])
        provisioning_uri = mfa.get_provisioning_uri(username)
        
        # Generate QR code path
        qr_code_path = f"mfa_qrcodes/{username}_mfa_qr.png"
        os.makedirs("mfa_qrcodes", exist_ok=True)
        
        # Generate and save QR code
        img = qrcode.make(provisioning_uri)
        img.save(qr_code_path)
        
        # Update database
        cursor.execute(
            "UPDATE users SET mfa_enabled=?, mfa_secret=? WHERE username=?",
            (True, mfa.secret, username)
        )
        self.conn.commit()
        
        # Save secret to file
        with open('qr_code.txt', 'w') as f:
            f.write(f"Secret: {mfa.secret}\n")
            f.write(f"QR Code saved to: {qr_code_path}\n")
        
        return mfa.secret, qr_code_path  # Return both values