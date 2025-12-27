import sqlite3
import os

def init_db():
    db_path = "database/forensics.db"
    os.makedirs("database", exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        with open("database/schema.sql", "r") as f:
            conn.executescript(f.read())
    print("[+] Database initialized.")
