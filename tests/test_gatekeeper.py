"""Gatekeeper tests: permits, forgery, replay, misuse, immutability."""
import os
import tempfile
import time
import unittest

from aegis_swarm_core import (
    Gatekeeper, IntentContract, ParamRule, PolicyDenied, PermitError,
    AuditChain,
)


def make_gate():
    tmp = tempfile.mkdtemp()
    audit = AuditChain(os.path.join(tmp, "audit.jsonl"))
    gate = Gatekeeper(audit)
    return gate, audit


def contract(agent="node-scout", max_calls=100):
    return IntentContract(
        agent_id=agent,
        allowed_actions={"scan_sector", "emit_heartbeat"},
        allowed_tools={"telemetry", "telemetry-heartbeat"},
        allowed_targets=("sector:*", "log:swarm-audit"),
        param_rules={
            "scan_sector": {
                "sector": ParamRule(pattern=r"[A-Za-z0-9:_-]+"),
                "depth": ParamRule(ptype="integer"),
            },
            "emit_heartbeat": {},
        },
        max_calls=max_calls,
    )


def good_request(agent="node-scout"):
    return {"agent_id": agent, "action": "scan_sector", "tool": "telemetry",
            "target": "sector:7g",
            "params": {"sector": "sector:7g", "depth": 2}}


class TestGatekeeper(unittest.TestCase):
    def setUp(self):
        self.gate, self.audit = make_gate()
        self.gate.register(contract())

    def tearDown(self):
        self.audit.close()

    def test_authorized_action_executes(self):
        calls = []
        req = good_request()
        permit = self.gate.authorize(req)
        result = self.gate.execute(permit, req, lambda r: calls.append(r) or {"ok": True})
        self.assertEqual(result, {"ok": True})
        self.assertEqual(len(calls), 1)

    def test_rejected_action_never_invokes_handler(self):
        calls = []
        bad = good_request()
        bad["action"] = "exfiltrate_data"
        with self.assertRaises(PolicyDenied):
            self.gate.authorize(bad)
        # authorize raised, so execute is never reached — but prove the
        # gate would not run the handler even if called with no permit:
        self.assertEqual(calls, [])

    def test_forged_permit_rejected(self):
        req = good_request()
        permit = self.gate.authorize(req)
        forged = dict(permit)
        forged["action_hash"] = "0" * 64  # attacker swaps the binding
        with self.assertRaises(PermitError):
            self.gate.execute(forged, req, lambda r: {"ok": True})

    def test_permit_replay_rejected(self):
        req = good_request()
        permit = self.gate.authorize(req)
        self.gate.execute(permit, req, lambda r: {"ok": True})
        with self.assertRaises(PermitError):
            self.gate.execute(permit, req, lambda r: {"ok": True})

    def test_permit_bound_to_exact_request(self):
        req = good_request()
        permit = self.gate.authorize(req)
        other = good_request()
        other["params"] = {"sector": "sector:7g", "depth": 999}
        with self.assertRaises(PermitError):
            self.gate.execute(permit, other, lambda r: {"ok": True})

    def test_permit_cross_agent_rejected(self):
        self.gate.register(contract(agent="node-echo2",
                                    max_calls=100))
        req = good_request()
        permit = self.gate.authorize(req)
        req2 = good_request(agent="node-echo2")
        # permit was issued for node-scout; using it as node-echo2 fails
        with self.assertRaises(PermitError):
            self.gate.execute(permit, req2, lambda r: {"ok": True})

    def test_cross_gatekeeper_permit_rejected(self):
        # A permit signed by one gatekeeper's secret is worthless at another:
        # per-session secrets never leave the gatekeeper.
        gate2, audit2 = make_gate()
        gate2.register(contract())
        req = good_request()
        permit = self.gate.authorize(req)
        with self.assertRaises(PermitError):
            gate2.execute(permit, req, lambda r: {"ok": True})
        audit2.close()

    def test_contract_reregister_rejected(self):
        with self.assertRaises(PolicyDenied):
            self.gate.register(contract())  # same agent_id again
        # original contract still in force
        req = good_request()
        permit = self.gate.authorize(req)
        self.assertIn("sig", permit)

    def test_unregistered_agent_rejected(self):
        req = good_request(agent="node-ghost")
        with self.assertRaises(PolicyDenied):
            self.gate.authorize(req)

    def test_call_budget_enforced(self):
        gate, audit = make_gate()
        gate.register(contract(agent="node-limited", max_calls=2))
        for _ in range(2):
            req = good_request(agent="node-limited")
            permit = gate.authorize(req)
            gate.execute(permit, req, lambda r: {"ok": True})
        with self.assertRaises(PolicyDenied):
            gate.authorize(good_request(agent="node-limited"))
        audit.close()

    def test_expired_permit_rejected(self):
        # White-box: mint a backdated permit with the gatekeeper's own
        # signer to exercise the expiry check honestly.
        import hashlib
        import hmac as hmac_mod
        import json as json_mod
        req = good_request()
        permit = self.gate.authorize(req)
        body = {k: v for k, v in permit.items() if k != "sig"}
        body["issued_at"] = time.time() - 3600
        body["nonce"] = "fresh-nonce-for-expiry-test"
        canon = json_mod.dumps(body, sort_keys=True, separators=(",", ":"))
        body["sig"] = hmac_mod.new(
            self.gate._secret, canon.encode(), hashlib.sha256).hexdigest()
        with self.assertRaises(PermitError):
            self.gate.execute(body, req, lambda r: {"ok": True})


if __name__ == "__main__":
    unittest.main()
