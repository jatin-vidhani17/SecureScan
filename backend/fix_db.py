import sqlite3
from database import DB_PATH

try:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE scans SET status='error' WHERE status='running'")
    conn.commit()
    print("Successfully updated running scans to error.")
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
