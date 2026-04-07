import sqlite3
import os

DB_FILE = 'users.db'

def check_db():
    if not os.path.exists(DB_FILE):
        print(f"Database file '{DB_FILE}' does not exist.")
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table = c.fetchone()
        if not table:
            print("Table 'users' does not exist.")
            return
            
        c.execute("SELECT username, email FROM users")
        users = c.fetchall()
        print(f"Found {len(users)} users.")
        for u in users:
            print(f"- {u[0]} ({u[1]})")
            
    except Exception as e:
        print(f"Error checking database: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    check_db()
