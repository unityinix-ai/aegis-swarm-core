"""Swarm integration tests: 5 nodes, gated actions, chained verdicts."""
import os
import tempfile
import unittest

from aegis_swarm_core import (
    Gatekeeper, PolicyDenied, AuditChain, verify_chain,
)
from aegis_swarm_core.swarm import SwarmNode, PERSONAS, run_swarm


def make_gate():
    tmp = tempfile.mkdtemp()
    audit = AuditChain(os.path.join(tmp, "audit.jsonl"))
    return Gatekeeper(audit), audit, os.path.join(tmp, "audit.jsonl")


class TestSwarm(unittest.TestCase):
    def test_five_nodes_run_clean(self):
        gate, audit, path = make_gate()
        results = run_swarm(gate, audit)
        audit.close()
        self.assertEqual(set(results), set(PERSONAS))
        for key, res in results.items():
            self.assertEqual(res["status"], "completed", key)
        check = verify_chain(path)
        self.assertTrue(check["ok"], check)
        # 5 contracts + 5 heartbeats + 5 heartbeat-actions + 5 domain actions
        # + 5x3 gate decisions... just assert a healthy minimum
        self.assertGreaterEqual(check["checked"], 15)

    def test_rogue_node_action_rejected_and_logged(self):
        gate, audit, path = make_gate()
        node = SwarmNode("strategist", gate, audit)
        node.heartbeat()  # legit traffic works
        with self.assertRaises(PolicyDenied):
            node.act("override_safeties", "analysis", "log:swarm-audit", {})
        # the rejection is in the log, and the chain still verifies
        audit.close()
        check = verify_chain(path)
        self.assertTrue(check["ok"], check)
        import json
        with open(path, encoding="utf-8") as f:
            events = [json.loads(ln) for ln in f if ln.strip()]
        rejections = [e for e in events if e["event_type"] == "action_rejected"]
        self.assertTrue(rejections)
        self.assertEqual(rejections[0]["data"]["action"], "override_safeties")

    def test_unknown_persona_rejected(self):
        gate, audit, _ = make_gate()
        with self.assertRaises(ValueError):
            SwarmNode("sukuna", gate, audit)
        audit.close()


if __name__ == "__main__":
    unittest.main()
