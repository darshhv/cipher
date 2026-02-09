import sqlite3
from datetime import datetime


class CipherTelemetry:
    def __init__(self, db_path="data/cipher_audit.db"):
        self.conn = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            timestamp TEXT,
            source_identity TEXT,
            destination_identity TEXT,
            decision TEXT
        )
        """)
        self.conn.commit()

    def log_event(self, source, destination, decision):
        self.conn.execute(
            "INSERT INTO security_events VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), source, destination, decision),
        )
        self.conn.commit()
