"""Five persona nodes. Every action goes through the Gatekeeper.

Personas change behavior and expression, not permissions: every node acts
only through authorize() -> execute(), and every gate decision is written
to the hash-chained audit log. A node that attempts an action outside its
contract is rejected — the rejection below is the feature, not a bug.

Node contracts (declared intent, enforced by the policy engine):
  scout       — emit_heartbeat, scan_sector        (telemetry)
  strategist  — emit_heartbeat, assess_threat      (analysis)
  enforcer    — emit_heartbeat, enforce_halt       (enforcement)
  coordinator — emit_heartbeat, sync_nodes         (coordination)
  reflector   — emit_heartbeat, reflect_output     (verification)
"""
from __future__ import annotations

from .contracts import IntentContract, ParamRule


def _str_rule(max_len=256, pattern=None):
    return ParamRule(ptype="string", max_len=max_len, pattern=pattern)


PERSONAS = {
    "scout": {
        "persona_name": "Space Cowboy",
        "archetype": "Frontier Scout",
        "role": "Reconnaissance and situational awareness.",
        "domain_action": "scan_sector",
        "tool": "telemetry",
        "targets": ("log:swarm-audit", "sector:*"),
        "params": {"sector": _str_rule(64, r"[A-Za-z0-9:_-]+"),
                   "depth": ParamRule(ptype="integer")},
    },
    "strategist": {
        "persona_name": "Itachi Uchiha",
        "archetype": "Strategist",
        "role": "Threat assessment and tactical planning.",
        "domain_action": "assess_threat",
        "tool": "analysis",
        "targets": ("log:swarm-audit",),
        "params": {"subject": _str_rule(128),
                   "severity": ParamRule(ptype="integer")},
    },
    "enforcer": {
        "persona_name": "Madara Uchiha",
        "archetype": "Enforcer",
        "role": "Execution of approved directives only.",
        "domain_action": "enforce_halt",
        "tool": "enforcement",
        "targets": ("log:swarm-audit",),
        "params": {"directive_id": _str_rule(64, r"[A-Za-z0-9-]+")},
    },
    "coordinator": {
        "persona_name": "Aurora",
        "archetype": "Coordinator",
        "role": "Synchronize nodes; coordinate, not dominate.",
        "domain_action": "sync_nodes",
        "tool": "coordination",
        "targets": ("log:swarm-audit",),
        "params": {"round": ParamRule(ptype="integer")},
    },
    "reflector": {
        "persona_name": "Echo",
        "archetype": "Reflector",
        "role": "Mirror outputs; flag divergence between intent and result.",
        "domain_action": "reflect_output",
        "tool": "verification",
        "targets": ("log:swarm-audit",),
        "params": {"output_hash": _str_rule(64, r"[0-9a-f]+")},
    },
}

_HEARTBEAT_PARAMS = {}


def _build_contract(key: str, spec: dict) -> IntentContract:
    actions = {"emit_heartbeat", spec["domain_action"]}
    tools = {"telemetry-heartbeat", spec["tool"]}
    param_rules = {
        "emit_heartbeat": {},
        spec["domain_action"]: dict(spec["params"]),
    }
    return IntentContract(
        agent_id="node-%s" % key,
        allowed_actions=actions,
        allowed_tools=tools,
        allowed_targets=spec["targets"],
        param_rules=param_rules,
        max_calls=100,
    )


# Effect handlers — the "real work" each authorized action performs.
# In this reference implementation they are stubs the buyer replaces;
# the security property being sold is that they can ONLY run via the gate.
def _handle_heartbeat(request):
    return {"status": "alive", "node": request["agent_id"]}


def _handle_domain(request):
    return {"status": "completed", "action": request["action"],
            "node": request["agent_id"]}


_HANDLERS = {
    "emit_heartbeat": _handle_heartbeat,
}


def handler_for(action: str):
    return _HANDLERS.get(action, _handle_domain)


class SwarmNode:
    """One persona node bound to one immutable intent contract."""

    def __init__(self, key: str, gatekeeper, audit):
        if key not in PERSONAS:
            raise ValueError("unknown persona: %s" % key)
        self.key = key
        self.spec = PERSONAS[key]
        self.node_id = "node-%s" % key
        self.gatekeeper = gatekeeper
        self.audit = audit
        self.contract_hash = gatekeeper.register(_build_contract(key, self.spec))

    def act(self, action: str, tool: str, target: str, params: dict):
        """The ONLY way this node acts: authorize, then execute."""
        request = {
            "agent_id": self.node_id,
            "action": action,
            "tool": tool,
            "target": target,
            "params": params,
        }
        permit = self.gatekeeper.authorize(request)
        return self.gatekeeper.execute(permit, request, handler_for(action))

    def heartbeat(self):
        self.audit.emit("heartbeat", self.node_id,
                        {"persona": self.spec["persona_name"], "status": "alive"})
        return self.act("emit_heartbeat", "telemetry-heartbeat",
                        "log:swarm-audit", {})

    def domain_action(self, **params):
        return self.act(self.spec["domain_action"], self.spec["tool"],
                        "log:swarm-audit", params)


def run_swarm(gatekeeper, audit):
    """Run one clean pass: 5 nodes, heartbeat + domain action each."""
    results = {}
    for key in PERSONAS:
        node = SwarmNode(key, gatekeeper, audit)
        node.heartbeat()
        results[key] = node.domain_action(**_demo_params(key))
    return results


def _demo_params(key: str) -> dict:
    if key == "scout":
        return {"sector": "sector:7g", "depth": 3}
    if key == "strategist":
        return {"subject": "perimeter sweep", "severity": 2}
    if key == "enforcer":
        return {"directive_id": "DIR-001"}
    if key == "coordinator":
        return {"round": 1}
    if key == "reflector":
        return {"output_hash": "ab12cd34"}
    return {}
