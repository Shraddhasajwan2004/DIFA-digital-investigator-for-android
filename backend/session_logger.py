import sqlite3
from datetime import datetime
import os

DB_PATH = os.path.join("database", "forensics.db")

def log_session(case_number, investigator_id, device, csv_path, hash_path, final_score, ):
    """
    Logs a forensic session into the SQLite database.
    """
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO sessions (case_number, investigator_id, device, timestamp, csv_path, hash_path, final_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (case_number, investigator_id, device, datetime.now().isoformat(), csv_path, hash_path, final_score))

    conn.commit()
    conn.close()
    print(f"[+] Session logged: {case_number} by {investigator_id}")



def get_sessions_by_investigator(investigator_id):
    """
    Retrieves all sessions for a given investigator.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT case_number, device, timestamp, csv_path, hash_path, final_score 
        FROM sessions 
        WHERE investigator_id = ? 
        ORDER BY timestamp DESC
    """, (investigator_id,))
    rows = cur.fetchall()
    conn.close()
    return rows
DB_PATH = "database/forensics.db"

def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device TEXT,
            csv_path TEXT,
            hash_path TEXT,
            workflow TEXT
        )
    """)
    conn.commit()
    conn.close()



def get_sessions(workflow=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if workflow:
        cur.execute("SELECT timestamp, device, csv_path, hash_path FROM sessions WHERE workflow=? ORDER BY id DESC", (workflow,))
    else:
        cur.execute("SELECT timestamp, device, csv_path, hash_path FROM sessions ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows
# ✅ Add this to the bottom of backend/session_logger.py

def save_to_db(timestamp, device, csv_path, hash_path, workflow="unknown"):
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO sessions (timestamp, device, csv_path, hash_path, workflow)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, device, csv_path, hash_path, workflow))
    conn.commit()
    conn.close()
    print(f"[+] Session saved: {timestamp} – {workflow}")
def get_session_by_id(session_id):
    """
    Retrieves a session by its ID.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    row = cur.fetchone()
    conn.close()
    return row if row else None
