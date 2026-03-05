import json
import sqlite3
from datetime import datetime, timezone


class CipherTelemetry:
    def __init__(self, db_path="data/cipher_audit.db"):
        self.conn = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        self.conn.execute(
            """
        CREATE TABLE IF NOT EXISTS security_events (
            timestamp TEXT,
            event_type TEXT,
            outcome TEXT,
            source_identity TEXT,
            destination_identity TEXT,
            decision TEXT,
            reason TEXT,
            details_json TEXT
        )
        """
        )
        self.conn.commit()

    def log_security_event(
        self,
        event_type,
        outcome,
        source_identity="",
        destination_identity="",
        decision="",
        reason="",
        details=None,
    ):
        self.conn.execute(
            "INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                event_type,
                outcome,
                source_identity,
                destination_identity,
                decision,
                reason,
                json.dumps(details or {}, sort_keys=True),
            ),
        )
        self.conn.commit()

    def log_event(self, source, destination, decision):
        """Backward-compatible wrapper for existing proxy/server code paths."""
        self.log_security_event(
            event_type="authorization.decision",
            outcome="success" if decision == "allow" else "denied",
            source_identity=source,
            destination_identity=destination,
            decision=decision,
        )
