"""Audit-chain tests: happy path, and every tamper mode detected."""
import json
import os
import tempfile
import unittest

from aegis_swarm_core import AuditChain, verify_chain


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "audit.jsonl")

    def _write(self, n=5):
        chain = AuditChain(self.path)
        for i in range(n):
            chain.emit("test_event", "node-x", {"i": i})
        chain.close()

    def test_clean_chain_verifies(self):
        self._write(5)
        result = verify_chain(self.path)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["checked"], 5)

    def test_empty_log_verifies(self):
        chain = AuditChain(self.path)
        chain.close()
        result = verify_chain(self.path)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["checked"], 0)

    def test_content_tamper_detected(self):
        self._write(5)
        with open(self.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        event = json.loads(lines[2])
        event["data"] = {"i": 999}  # attacker alters a payload, keeps the hash
        lines[2] = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        result = verify_chain(self.path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed_at"], 2)

    def test_deletion_detected(self):
        self._write(5)
        with open(self.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        del lines[2]  # attacker removes an event
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        result = verify_chain(self.path)
        self.assertFalse(result["ok"])
        # seq 3 now points at a prev_hash that no longer exists in the file
        self.assertEqual(result["failed_at"], 3)

    def test_garbage_line_detected(self):
        self._write(3)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("this is not json\n")
        result = verify_chain(self.path)
        self.assertFalse(result["ok"])

    def test_missing_file_reported(self):
        result = verify_chain(os.path.join(self.tmp, "nope.jsonl"))
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["reason"])

    def test_chain_resumes_across_reopens(self):
        self._write(3)
        chain = AuditChain(self.path)  # reopens existing log
        chain.emit("test_event", "node-x", {"i": 99})
        chain.close()
        result = verify_chain(self.path)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["checked"], 4)


if __name__ == "__main__":
    unittest.main()
