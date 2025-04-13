import uuid
from getpass import getpass
from auth import AuthManager
from file_client import FileClient
from audit import AuditLogger
import sqlite3
import os

class SecureStorageApp:
    def __init__(self):
        self.auth = AuthManager()
        self.audit = AuditLogger()
        self.current_user = None
        self.current_user_id = None
        self.file_client = None
        
    def run(self):
        print("=== Secure Storage System ===")
        while True:
            if not self.current_user:
                self.show_login_menu()
            else:
                self.show_main_menu()
    
    def show_login_menu(self):
        print("\nMain Menu")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Select option: ")
        
        if choice == "1":
            self.register_user()
        elif choice == "2":
            self.login_user()
        elif choice == "3":
            print("Goodbye!")
            exit()
        else:
            print("Invalid choice, please try again.")
    
    def show_main_menu(self):
        print(f"\nWelcome, {self.current_user}!")
        print("1. Upload File")
        print("2. Download File")
        print("3. List My Files")
        print("4. Share File")
        print("5. Reset Password")
        print("6. MFA Settings")
        print("7. View Activity Logs")
        print("8. Logout")
        
        choice = input("Select option: ")
        
        if choice == "1":
            self.upload_file()
        elif choice == "2":
            self.download_file()
        elif choice == "3":
            self.list_files()
        elif choice == "4":
            self.share_file()
        elif choice == "5":
            self.reset_password()
        elif choice == "6":
            self.mfa_settings()
        elif choice == "7":
            self.view_logs()
        elif choice == "8":
            self.logout()
        else:
            print("Invalid choice, please try again.")
    
    def register_user(self):
        print("\nUser Registration")
        username = input("Username: ")
        password = getpass("Password: ")
        
        if self.auth.register(username, password):
            print("Registration successful!")
            self.audit.log_action(None, "register", username)
        else:
            print("Registration failed - username may already exist.")
    
    def login_user(self):
        print("\nUser Login")
        username = input("Username: ")
        password = getpass("Password: ")
        
        result = self.auth.login(username, password)
        
        if result["status"] == "success":
            self.current_user = username
            self.current_user_id = result["user_id"]
            self.file_client = FileClient(self.current_user_id)
            print("Login successful!")
            self.audit.log_action(self.current_user_id, "login", "success")
        elif result["status"] == "mfa_required":
            self.handle_mfa(username, result["user_id"])
        else:
            print("Login failed - invalid username or password.")
            self.audit.log_action(None, "login_failed", username)
    
    def handle_mfa(self, username, user_id):
        print("\nMulti-Factor Authentication Required")
        code = input("Enter 6-digit verification code: ")
        
        if self.auth.verify_mfa(username, code):
            self.current_user = username
            self.current_user_id = user_id
            self.file_client = FileClient(self.current_user_id)
            print("MFA verification successful! Login complete.")
            self.audit.log_action(user_id, "login_mfa", "success")
        else:
            print("MFA verification failed.")
            self.audit.log_action(user_id, "login_mfa", "failed")
    
    def upload_file(self):
        print("\nFile Upload")
        filepath = input("Enter file path to upload: ")
        
        if not os.path.exists(filepath):
            print("File does not exist.")
            return
        
        filename = os.path.basename(filepath)
        file_id, encrypted_path = self.file_client.encrypt_file(filepath)
        
        conn = sqlite3.connect('secure_storage.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (file_id, owner_id, filename, encrypted_path) VALUES (?, ?, ?, ?)",
            (file_id, self.current_user_id, filename, encrypted_path)
        )
        conn.commit()
        conn.close()
        
        print(f"File uploaded successfully! File ID: {file_id}")
        self.audit.log_action(self.current_user_id, "upload", file_id)
    
    def download_file(self):
        print("\nFile Download")
        self.list_files()
        file_id = input("Enter File ID to download: ")
        
        conn = sqlite3.connect('secure_storage.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT filename, encrypted_path FROM files WHERE file_id=? AND (owner_id=? OR shared_with=?)",
            (file_id, self.current_user_id, self.current_user_id)
        )
        file = cursor.fetchone()
        conn.close()
        
        if file:
            filename, encrypted_path = file
            save_path = input(f"Enter path to save {filename} (press Enter for current directory): ")
            save_path = save_path if save_path else "."
            
            decrypted_path = self.file_client.decrypt_file(encrypted_path, os.path.join(save_path, filename))
            print(f"File downloaded to: {decrypted_path}")
            self.audit.log_action(self.current_user_id, "download", file_id)
        else:
            print("File not found or you don't have permission to access it.")
    
    def list_files(self):
        print("\nYour Files:")
        conn = sqlite3.connect('secure_storage.db')
        cursor = conn.cursor()
        
        # Owner files
        cursor.execute(
            "SELECT file_id, filename FROM files WHERE owner_id=?",
            (self.current_user_id,)
        )
        print("\nOwned Files:")
        for file in cursor.fetchall():
            print(f"ID: {file[0]}, Name: {file[1]}")
        
        # Shared files
        cursor.execute(
            "SELECT file_id, filename FROM files WHERE shared_with=?",
            (self.current_user_id,)
        )
        print("\nShared With You:")
        for file in cursor.fetchall():
            print(f"ID: {file[0]}, Name: {file[1]}")
        
        conn.close()
    
    def share_file(self):
        print("\nShare File")
        self.list_files()
        file_id = input("Enter File ID to share: ")
        target_user = input("Enter username to share with: ")
        
        # Get target user ID
        conn = sqlite3.connect('secure_storage.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id FROM users WHERE username=?",
            (target_user,)
        )
        target = cursor.fetchone()
        
        if not target:
            print("User not found.")
            conn.close()
            return
        
        # Check if user owns the file
        cursor.execute(
            "SELECT owner_id FROM files WHERE file_id=?",
            (file_id,)
        )
        file = cursor.fetchone()
        
        if not file or file[0] != self.current_user_id:
            print("File not found or you don't own this file.")
            conn.close()
            return
        
        # Update shared_with field
        cursor.execute(
            "UPDATE files SET shared_with=? WHERE file_id=?",
            (target[0], file_id)
        )
        conn.commit()
        conn.close()
        
        print(f"File shared successfully with {target_user}!")
        self.audit.log_action(self.current_user_id, "share", f"{file_id} with {target_user}")
    
    def reset_password(self):
        print("\nReset Password")
        old_password = getpass("Current password: ")
        new_password = getpass("New password: ")
        confirm_password = getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("New passwords don't match.")
            return
        
        if self.auth.reset_password(self.current_user, old_password, new_password):
            print("Password reset successful!")
            self.audit.log_action(self.current_user_id, "reset_password", "success")
        else:
            print("Password reset failed - incorrect current password.")
            self.audit.log_action(self.current_user_id, "reset_password_attempt", "failed")
    
    def mfa_settings(self):
        print("\nMFA Settings")
        mfa_enabled = self.auth.is_mfa_enabled(self.current_user)
        
        if mfa_enabled:
            print("1. Disable MFA")
            print("2. Back")
            choice = input("Select option: ")
            
            if choice == "1":
                code = input("Enter current verification code: ")
                if self.auth.disable_mfa(self.current_user, code):
                    print("MFA disabled successfully!")
                else:
                    print("Failed to disable MFA - invalid code.")
        else:
            print("1. Enable MFA")
            print("2. Back")
            choice = input("Select option: ")
            
            if choice == "1":
                secret, qr_path = self.auth.enable_mfa(self.current_user)
                print(f"\nMFA enabled successfully!")
                print(f"Secret: {secret}")
                print(f"QR code saved to: {qr_path}")
                print("\nPlease scan the QR code with your authenticator app:")
                print(f"Or manually enter the secret: {secret}")
    
    def view_logs(self):
        print("\nActivity Logs")
        conn = sqlite3.connect('secure_storage.db')
        cursor = conn.cursor()
        
        # Check if admin (first user is considered admin)
        cursor.execute("SELECT user_id FROM users ORDER BY rowid LIMIT 1")
        admin_id = cursor.fetchone()[0]
        
        if self.current_user_id == admin_id:
            # Admin can see all logs
            cursor.execute(
                "SELECT timestamp, user_id, action, target FROM audit_logs ORDER BY timestamp DESC LIMIT 50"
            )
        else:
            # Regular users can only see their own logs
            cursor.execute(
                "SELECT timestamp, user_id, action, target FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50",
                (self.current_user_id,)
            )
        
        print("\nRecent Activity:")
        for log in cursor.fetchall():
            print(f"{log[0]} - User {log[1]}: {log[2]} {log[3]}")
        
        conn.close()
    
    def logout(self):
        print(f"\nGoodbye, {self.current_user}!")
        self.audit.log_action(self.current_user_id, "logout", "success")
        self.current_user = None
        self.current_user_id = None
        self.file_client = None

if __name__ == "__main__":
    app = SecureStorageApp()
    os.makedirs("mfa_qrcodes", exist_ok=True)
    app.run()