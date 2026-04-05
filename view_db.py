import sqlite3
import os

db_path = os.path.join("backend", "securescan.db")

def query_table(table_name):
    print(f"\n--- {table_name.upper()} ---")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT 5")
        rows = cursor.fetchall()
        
        # Get column names
        cursor.execute(f"PRAGMA table_info({table_name})")
        cols = [col[1] for col in cursor.fetchall()]
        print(f"Columns: {', '.join(cols)}")
        
        for row in rows:
            print(row)
        conn.close()
    except Exception as e:
        print(f"Error querying {table_name}: {e}")

if __name__ == "__main__":
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
    else:
        for table in ["scans", "vulnerabilities", "logs"]:
            query_table(table)
