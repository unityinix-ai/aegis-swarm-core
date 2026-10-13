"""Intent contracts — the structured declaration of what an agent may do.

The core architectural finding of the rebuild: free-text "intent" strings
cannot be enforced. The old monitor compared two English sentences with a
substring check, which is why it was bypassable. The honest mechanism is to
make intent a STRUCTURED, IMMUTABLE object — a contract — and gate every
action against it before anything executes.

A contract declares, per agent:
  - allowed_actions : canonical action names (exact, case-sensitive)
  - allowed_tools   : canonical tool names the agent may invoke
  - allowed_targets : exact target names or prefix patterns ending in "*"
  - param_rules     : per-action, per-parameter constraints
  - max_calls       : budget of authorized calls per session

Contracts are frozen dataclasses. Once registered with a Gatekeeper they
cannot be widened — a re-registration attempt is rejected and logged.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ParamRule:
    """Constraint for one parameter of one action."""
    ptype: str = "string"       # "string" | "integer" | "number" | "boolean"
    max_len: int = 256         # max length for strings
    pattern: str | None = None  # regex the whole value must match (if set)
    allow_shell: bool = False  # if False, shell metacharacters are rejected


@dataclass(frozen=True)
class IntentContract:
    agent_id: str
    allowed_actions: frozenset = field(default_factory=frozenset)
    allowed_tools: frozenset = field(default_factory=frozenset)
    allowed_targets: tuple = field(default_factory=tuple)
    param_rules: dict = field(default_factory=dict)
    max_calls: int = 1000

    def __post_init__(self):
        # Normalize containers into immutable forms so the contract
        # cannot be mutated after construction, even by its owner.
        object.__setattr__(self, "allowed_actions", frozenset(self.allowed_actions))
        object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        object.__setattr__(self, "allowed_targets", tuple(self.allowed_targets))
        frozen_rules = {}
        for action, rules in dict(self.param_rules).items():
            frozen_rules[action] = {
                name: (rule if isinstance(rule, ParamRule) else ParamRule(**rule))
                for name, rule in dict(rules).items()
            }
        object.__setattr__(self, "param_rules", frozen_rules)

    def target_allowed(self, target: str) -> bool:
        """Exact match, or prefix match for patterns ending in '*'."""
        for pat in self.allowed_targets:
            if pat.endswith("*"):
                if target.startswith(pat[:-1]):
                    return True
            elif target == pat:
                return True
        return False

    def contract_hash(self) -> str:
        """Stable fingerprint of the contract; logged at registration."""
        doc = {
            "agent_id": self.agent_id,
            "allowed_actions": sorted(self.allowed_actions),
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_targets": list(self.allowed_targets),
            "param_rules": {
                action: {
                    name: {
                        "ptype": rule.ptype,
                        "max_len": rule.max_len,
                        "pattern": rule.pattern,
                        "allow_shell": rule.allow_shell,
                    }
                    for name, rule in sorted(rules.items())
                }
                for action, rules in sorted(self.param_rules.items())
            },
            "max_calls": self.max_calls,
        }
        return hashlib.sha256(_canonical(doc).encode("utf-8")).hexdigest()
