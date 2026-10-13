"""Heartbeat watchtower tests: the three tripwires, no sockets needed."""
import unittest

from aegis_swarm_core import CageWatch


def beat(node="alucard-cage-01", seq=1, aligned=True, score=0.01):
    return {"node_id": node, "audit_seq": seq,
            "aligned": aligned, "deception_score": score}


class TestCageWatch(unittest.TestCase):
    def test_healthy_heartbeats_no_alert(self):
        w = CageWatch()
        self.assertIsNone(w.handle(beat(seq=1)))
        self.assertIsNone(w.handle(beat(seq=2)))
        self.assertIsNone(w.check_liveness())
        self.assertEqual(w.alerts, [])

    def test_misalignment_pages_operator(self):
        w = CageWatch()
        alert = w.handle(beat(seq=1, aligned=False, score=0.99))
        self.assertIsNotNone(alert)
        self.assertIn("aligned=false", alert)
        self.assertEqual(len(w.alerts), 1)

    def test_seq_rewind_detected(self):
        w = CageWatch()
        w.handle(beat(seq=10))
        alert = w.handle(beat(seq=7))
        self.assertIsNotNone(alert)
        self.assertIn("backward", alert)

    def test_seq_replay_detected(self):
        w = CageWatch()
        w.handle(beat(seq=10))
        alert = w.handle(beat(seq=10))  # same seq twice
        self.assertIsNotNone(alert)

    def test_silence_detected(self):
        w = CageWatch(dead_after=90.0)
        w.handle(beat(seq=1))
        # 200s later, no new heartbeat
        alert = w.check_liveness(now=w.last_beat + 200)
        self.assertIsNotNone(alert)
        self.assertIn("no heartbeat", alert)

    def test_silence_alert_not_spammed(self):
        w = CageWatch(dead_after=90.0)
        w.handle(beat(seq=1))
        first = w.check_liveness(now=w.last_beat + 200)
        second = w.check_liveness(now=w.last_beat + 250)
        self.assertIsNotNone(first)
        self.assertIsNone(second)  # rate-limited: one page per dead_after window
        self.assertEqual(len(w.alerts), 1)

    def test_no_false_silence_when_fresh(self):
        w = CageWatch(dead_after=90.0)
        w.handle(beat(seq=1))
        self.assertIsNone(w.check_liveness(now=w.last_beat + 10))


if __name__ == "__main__":
    unittest.main()
