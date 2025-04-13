import sqlite3
import os

def init_database():
    """Initialize database and required tables"""
    # Create data directory if not exists
    os.makedirs('encrypted_files', exist_ok=True)
    
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        mfa_enabled BOOLEAN DEFAULT FALSE,
        mfa_secret TEXT
    )
    """)

    # Create files table with sharing capability
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY,
        owner_id TEXT,
        filename TEXT,
        encrypted_path TEXT,
        shared_with TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(user_id),
        FOREIGN KEY (shared_with) REFERENCES users(user_id)
    )
    """)

    # Create audit logs table (now handled by AuditLogger)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        log_id TEXT PRIMARY KEY,
        user_id TEXT,
        action TEXT,
        target TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
    """)

    conn.commit()
    conn.close()
    print("Database initialization completed!")

if __name__ == "__main__":
    init_database()