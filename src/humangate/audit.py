"""Append-only audit log with a sha256 hash chain.

Every approval request and every decision (approve / deny / timeout) is appended
as one JSON object per line. Each entry carries ``prev_hash`` — the sha256 of the
previous line — so deleting or editing a line breaks the chain and is detectable
via :meth:`AuditLog.verify`.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Iterator

GENESIS_HASH = "0" * 64


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        if not os.path.exists(path):
            open(path, "a", encoding="utf-8").close()

    def _last_hash(self) -> str:
        last = GENESIS_HASH
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if line:
                        last = _hash_line(line)
        except FileNotFoundError:
            pass
        return last

    def append(self, event: str, **fields) -> dict:
        """Append one audit event. Returns the entry written."""
        entry = {
            "ts": time.time(),
            "event": event,
            "prev_hash": None,  # filled in below
        }
        entry.update(fields)
        with self._lock:
            entry["prev_hash"] = self._last_hash()
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry

    def entries(self) -> Iterator[dict]:
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> tuple[bool, str]:
        """Verify the hash chain. Returns (ok, message)."""
        prev = GENESIS_HASH
        count = 0
        for entry in self.entries():
            if entry.get("prev_hash") != prev:
                return False, f"chain broken at entry {count} (event={entry.get('event')})"
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            prev = _hash_line(line)
            count += 1
        return True, f"ok: {count} entries, chain intact"
