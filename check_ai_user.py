
import sqlite3
import os

DB_PATH = os.path.join("database", "xuanchat.db")

def check_db():
    if not os.path.exists(DB_PATH):
        print("DB not found")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check is_ai column
    cur.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cur.fetchall()]
    print(f"Columns in users: {columns}")
    
    if "is_ai" in columns:
        print("is_ai column exists")
    else:
        print("is_ai column MISSING")

    # Check AI user
    cur.execute("SELECT * FROM users WHERE username = ?", ("内小妹",))
    user = cur.fetchone()
    if user:
        print(f"User found: {dict(user)}")
    else:
        print("User '内小妹' NOT found")

    conn.close()

if __name__ == "__main__":
    check_db()
