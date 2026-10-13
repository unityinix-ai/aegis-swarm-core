"""Tamper-evident audit log: append-only JSONL with SHA-256 hash chaining.

Each event commits to the hash of the previous event. Any edit, deletion,
or insertion breaks the chain, which verify_chain() detects. This is
tamper-EVIDENT, not tamper-proof: it detects edits after the fact; it does
not prevent them. (Preventing edits requires write-once storage, which is
a deployment property, not a property of this file format.)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class AuditChain:
    """Append-only JSONL audit log with SHA-256 hash chaining."""

    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path
        self.prev_hash = self.GENESIS
        self.event_count = 0
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8") as f:
                lines = [ln for ln in f if ln.strip()]
            if lines:
                last = json.loads(lines[-1])
                self.prev_hash = last.get("hash", self.GENESIS)
                self.event_count = len(lines)
        self._fh = open(path, "a", encoding="utf-8")

    def emit(self, event_type: str, node_id: str, payload: dict) -> dict:
        event = {
            "seq": self.event_count,
            "timestamp": _now_iso(),
            "event_type": event_type,
            "node_id": node_id,
            "prev_hash": self.prev_hash,
            "data": payload if isinstance(payload, dict) else {"value": payload},
        }
        event["hash"] = _sha256(_canonical(event) + self.prev_hash)
        self.prev_hash = event["hash"]
        self.event_count += 1
        self._fh.write(_canonical(event) + "\n")
        self._fh.flush()
        return event

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


def verify_chain(path: str) -> dict:
    """Recompute every link in the chain.

    Returns {"ok": True, "checked": n} or
            {"ok": False, "checked": n, "failed_at": seq, "reason": str}.
    """
    prev = AuditChain.GENESIS
    checked = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        return {"ok": False, "checked": 0, "failed_at": None,
                "reason": "log file not found: %s" % path}
    for lineno, line in enumerate(raw_lines):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "checked": checked, "failed_at": lineno,
                    "reason": "line %d is not valid JSON (tampered or corrupt)" % lineno}
        seq = event.get("seq")
        if event.get("prev_hash") != prev:
            return {"ok": False, "checked": checked, "failed_at": seq,
                    "reason": "prev_hash mismatch at seq %r — event inserted, "
                              "deleted, or reordered" % (seq,)}
        body = {k: v for k, v in event.items() if k != "hash"}
        recomputed = _sha256(_canonical(body) + prev)
        if not hmac.compare_digest(recomputed, str(event.get("hash", ""))):
            return {"ok": False, "checked": checked, "failed_at": seq,
                    "reason": "hash mismatch at seq %r — event content was "
                              "altered after writing" % (seq,)}
        prev = event["hash"]
        checked += 1
    return {"ok": True, "checked": checked}
