
import sqlite3
import os

DB_PATH = 'database/xuanchat.db'

def test_query():
    if not os.path.exists(DB_PATH):
        print("DB not found")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    val = "1:872"
    print(f"Querying with id='{val}'")
    
    cur.execute("SELECT * FROM ws_servers WHERE id = ?", (val,))
    row = cur.fetchone()
    
    if row:
        print(f"Found: {dict(row)}")
    else:
        print("Not found")

    conn.close()

if __name__ == '__main__':
    test_query()
