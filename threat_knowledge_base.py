import sqlite3
import csv
import os

DB_FILE = "threat_intel.db"

def init_db():
    """Initialize the SQLite database for local threat intelligence."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Create Threats Table
    # Hash is primary key to prevent duplicates
    c.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            hash_id TEXT PRIMARY KEY,
            name TEXT,
            type TEXT,
            description TEXT,
            related_cves TEXT,
            severity TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_threat(hash_str):
    """Retrieve threat details by hash."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM threats WHERE hash_id=?", (hash_str,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            "hash": row[0],
            "name": row[1],
            "type": row[2],
            "description": row[3],
            "related_cves": row[4],
            "severity": row[5]
        }
    return None

def add_threat(hash_str, name, threat_type, description, related_cves, severity):
    """Add a new threat to the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR REPLACE INTO threats (hash_id, name, type, description, related_cves, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (hash_str, name, threat_type, description, related_cves, severity))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def import_from_csv(filename):
    """Import threat data from a CSV file."""
    count = 0
    if not os.path.exists(filename):
        return 0
        
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader, None) # Skip header if present
        
        for row in reader:
            if len(row) >= 6:
                add_threat(row[0], row[1], row[2], row[3], row[4], row[5])
                count += 1
    return count
