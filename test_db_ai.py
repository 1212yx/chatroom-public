
from database.db import get_ai_user, get_default_ai_model, get_connection

try:
    user = get_ai_user()
    print(f"AI User: {dict(user) if user else None}")
    
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_models")
    rows = cur.fetchall()
    print(f"All Models ({len(rows)}):")
    for row in rows:
        print(dict(row))
    conn.close()

except Exception as e:
    print(f"Error: {e}")
