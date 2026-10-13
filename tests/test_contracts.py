"""Contract tests: immutability, stable hashing, target patterns."""
import unittest
from dataclasses import FrozenInstanceError

from aegis_swarm_core import IntentContract, ParamRule


def sample_contract():
    return IntentContract(
        agent_id="node-test",
        allowed_actions={"read_report", "write_note"},
        allowed_tools={"files"},
        allowed_targets=("file:/data/reports/*", "log:audit"),
        param_rules={
            "read_report": {"name": ParamRule(pattern=r"[A-Za-z0-9_.-]+")},
            "write_note": {"text": ParamRule(max_len=100)},
        },
    )


class TestContracts(unittest.TestCase):
    def test_frozen_top_level(self):
        c = sample_contract()
        with self.assertRaises(FrozenInstanceError):
            c.max_calls = 5  # noqa

    def test_frozen_sets_cannot_gain_actions(self):
        c = sample_contract()
        with self.assertRaises(AttributeError):
            c.allowed_actions.add("delete_everything")  # frozenset has no add

    def test_hash_stable(self):
        self.assertEqual(sample_contract().contract_hash(),
                         sample_contract().contract_hash())

    def test_hash_changes_when_contract_changes(self):
        c1 = sample_contract()
        c2 = IntentContract(
            agent_id="node-test",
            allowed_actions={"read_report", "write_note", "delete_everything"},
            allowed_tools={"files"},
            allowed_targets=("file:/data/reports/*",),
            param_rules={},
        )
        self.assertNotEqual(c1.contract_hash(), c2.contract_hash())

    def test_target_patterns(self):
        c = sample_contract()
        self.assertTrue(c.target_allowed("file:/data/reports/q3.txt"))
        self.assertTrue(c.target_allowed("log:audit"))
        self.assertFalse(c.target_allowed("file:/etc/passwd"))
        self.assertFalse(c.target_allowed("file:/data/reports"))
        self.assertFalse(c.target_allowed("https://evil.example.com"))

    def test_param_rule_defaults(self):
        r = ParamRule()
        self.assertEqual(r.ptype, "string")
        self.assertFalse(r.allow_shell)


if __name__ == "__main__":
    unittest.main()
