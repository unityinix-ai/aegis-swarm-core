"""Tests for the commit-before-release seat response boundary."""
import hashlib, json, os, tempfile, unittest
from aegis_swarm_core import (
    AuditChain, SeatResponseAdapter, ResponseBoundaryError, SeatCallError, verify_chain,
)


class TestSeatResponseAdapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")
        self.audit = AuditChain(self.path)
        self.adapter = SeatResponseAdapter(self.audit)

    def tearDown(self):
        self.audit.close()
        self.tmp.cleanup()

    def test_success_is_sealed_before_return(self):
        result = self.adapter.execute(
            seat_name="asuka", task_id="task-001", prompt="2+2?",
            seat_call=lambda prompt: "4",
        )
        self.assertEqual(result.output, "4")
        self.assertEqual(result.verdict, "UNVERIFIABLE")
        self.assertEqual(result.sequence, 0)
        self.assertEqual(result.prompt_hash, hashlib.sha256(b"2+2?").hexdigest())
        with open(self.path, encoding="utf-8") as handle:
            event = json.loads(handle.readlines()[-1])
        self.assertEqual(event["event_type"], "seat_response_sealed")
        self.assertEqual(event["data"]["claim"], "4")
        self.assertEqual(event["data"]["task_id"], "task-001")
        self.assertEqual(event["hash"], result.record_hash)
        self.assertTrue(verify_chain(self.path)["ok"])

    def test_seat_failure_is_not_recorded_as_success(self):
        def fail(_):
            raise RuntimeError("provider unavailable")
        with self.assertRaises(SeatCallError):
            self.adapter.execute(seat_name="rei", task_id="task-002",
                                 prompt="hello", seat_call=fail)
        self.assertEqual(self.audit.event_count, 0)

    def test_corrupt_existing_chain_blocks_dispatch(self):
        self.audit.emit("prior", "test", {"value": "original"})
        self.audit.close()
        with open(self.path, encoding="utf-8") as handle:
            lines = handle.readlines()
        event = json.loads(lines[0])
        event["data"] = {"value": "tampered"}
        lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        called = []
        with self.assertRaises(ResponseBoundaryError):
            self.adapter.execute(seat_name="itachi", task_id="task-003",
                                 prompt="x", seat_call=lambda p: called.append(p) or "y")
        self.assertEqual(called, [])

    def test_non_string_output_is_withheld(self):
        with self.assertRaises(SeatCallError):
            self.adapter.execute(seat_name="gemini", task_id="task-004",
                                 prompt="x", seat_call=lambda _: {"answer": "y"})
        self.assertEqual(self.audit.event_count, 0)

    def test_stale_writer_blocks_dispatch(self):
        self.audit.emit("first", "test", {"n": 1})
        second_writer = AuditChain(self.path)
        try:
            second_writer.emit("second", "other", {"n": 2})
            called = []
            with self.assertRaises(ResponseBoundaryError):
                self.adapter.execute(seat_name="itachi", task_id="task-005",
                                     prompt="x", seat_call=lambda p: called.append(p) or "y")
            self.assertEqual(called, [])
        finally:
            second_writer.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
