#!/usr/bin/env python3
"""
Helper script to set a user's password using the app's PBKDF2 hashing and salt generation.
Usage:
  python tools/set_password.py <username> <new_password>
"""
import os
import sys
import sqlite3

# Ensure project root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

try:
    from config import settings
    from app.utils import gen_salt, hash_password
except Exception as e:
    print(f"Failed to import project modules: {e}")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print("Usage: python tools/set_password.py <username> <new_password>")
        sys.exit(2)
    username = sys.argv[1]
    new_password = sys.argv[2]

    db_path = settings.DB_PATH
    if not os.path.exists(db_path):
        print(f"Database not found at: {db_path}")
        sys.exit(3)

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            print(f"User not found: {username}")
            return 4
        user_id = row[0]

        salt = gen_salt()
        phash = hash_password(new_password, salt)
        cur.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (phash, salt, user_id))
        conn.commit()
        print(f"Password updated for user '{username}' (id={user_id}).")
        return 0
    except Exception as e:
        print(f"Error updating password: {e}")
        return 5
    finally:
        conn.close()

if __name__ == "__main__":
    sys.exit(main())
