-- Investigators table
CREATE TABLE IF NOT EXISTS investigators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigator_name TEXT NOT NULL,
    organization TEXT NOT NULL,
    investigator_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL,
    investigator_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (investigator_id) REFERENCES investigators(investigator_id)
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL,
    investigator_id TEXT NOT NULL,
    device TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    csv_path TEXT,
    hash_path TEXT,
    final_score INTEGER,
    FOREIGN KEY (investigator_id) REFERENCES investigators(investigator_id)
);


