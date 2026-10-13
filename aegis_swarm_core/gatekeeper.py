"""Gatekeeper — the only path from intent to effect.

Architecture:
  1. register(contract) — binds an immutable IntentContract to an agent id.
     Re-registration is rejected: contracts cannot be widened at runtime.
  2. authorize(request) — runs the PolicyEngine BEFORE anything executes.
     On success returns an HMAC-SHA256-signed permit. On failure raises
     PolicyDenied and logs the rejection. The effect handler is NEVER
     invoked for a denied request.
  3. execute(permit, request, handler) — verifies the permit, then and
     only then invokes the handler.

A permit binds agent_id + the canonical hash of the exact request +
a one-time nonce, signed with a per-session secret that never leaves
this object. Forgery, replay, cross-agent reuse, and action substitution
are all rejected.

Honest boundary: this guarantees that every execution THROUGH the gate
was authorized. Python cannot stop a process from calling its own
functions directly; a deployment needing OS-level enforcement would run
effect handlers in a separate process behind this gatekeeper. That is
out of scope for this reference implementation — and it is stated here
instead of being hidden.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from .policy import PolicyEngine, Decision

PERMIT_TTL_SECONDS = 300


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _action_hash(request: dict) -> str:
    return hashlib.sha256(_canonical(request).encode("utf-8")).hexdigest()


class PermitError(Exception):
    """The permit was forged, replayed, mismatched, or expired."""


class PolicyDenied(Exception):
    """The policy engine refused the request. Carries the Decision."""

    def __init__(self, decision: Decision):
        self.decision = decision
        rules = ", ".join(rule for rule, _ in decision.violations)
        super().__init__("policy denied: %s" % rules)


class Gatekeeper:
    def __init__(self, audit):
        self._secret = secrets.token_bytes(32)
        self._engine = PolicyEngine()
        self._contracts = {}
        self._used_nonces = set()
        self._call_counts = {}
        self.audit = audit

    # -- contracts ------------------------------------------------------
    def register(self, contract) -> str:
        """Bind a contract to its agent. Raises PolicyDenied on re-register."""
        agent_id = contract.agent_id
        if agent_id in self._contracts:
            self.audit.emit(
                "contract_reregister_rejected", "gatekeeper",
                {"agent_id": agent_id,
                 "reason": "contracts are immutable once registered"},
            )
            raise PolicyDenied(Decision(
                allowed=False,
                violations=[("CONTRACT_IMMUTABLE",
                             "contract for %s already registered; widening denied"
                             % agent_id)],
            ))
        contract_hash = contract.contract_hash()
        self._contracts[agent_id] = contract
        self._call_counts[agent_id] = 0
        self.audit.emit(
            "contract_registered", "gatekeeper",
            {"agent_id": agent_id,
             "contract_hash": contract_hash,
             "allowed_actions": sorted(contract.allowed_actions)},
        )
        return contract_hash

    # -- authorization --------------------------------------------------
    def authorize(self, request: dict) -> dict:
        """Evaluate the request. Returns a signed permit, or raises PolicyDenied."""
        agent_id = request.get("agent_id", "?")
        contract = self._contracts.get(agent_id)
        if contract is None:
            decision = Decision(
                allowed=False,
                violations=[("NO_CONTRACT",
                             "no contract registered for %s" % agent_id)],
            )
            self.audit.emit("action_rejected", agent_id,
                            {"request": request, "violations": decision.violations})
            raise PolicyDenied(decision)
        if self._call_counts.get(agent_id, 0) >= contract.max_calls:
            decision = Decision(
                allowed=False,
                violations=[("CALL_BUDGET_EXCEEDED",
                             "agent %s exceeded max_calls=%d"
                             % (agent_id, contract.max_calls))],
            )
            self.audit.emit("action_rejected", agent_id,
                            {"request": request, "violations": decision.violations})
            raise PolicyDenied(decision)
        decision = self._engine.evaluate(contract, request)
        if not decision.allowed:
            self.audit.emit(
                "action_rejected", agent_id,
                {"action": request.get("action"),
                 "violations": decision.violations},
            )
            raise PolicyDenied(decision)
        permit = {
            "agent_id": agent_id,
            "action_hash": _action_hash(request),
            "nonce": secrets.token_hex(16),
            "issued_at": time.time(),
        }
        permit["sig"] = hmac.new(
            self._secret, _canonical(permit).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self._call_counts[agent_id] += 1
        self.audit.emit(
            "action_authorized", agent_id,
            {"action": request.get("action"),
             "action_hash": permit["action_hash"],
             "nonce": permit["nonce"]},
        )
        return permit

    # -- execution ------------------------------------------------------
    def execute(self, permit: dict, request: dict, handler):
        """Verify the permit, then invoke the handler. Raises PermitError."""
        agent_id = request.get("agent_id", "?")
        try:
            sig = permit["sig"]
            body = {k: v for k, v in permit.items() if k != "sig"}
        except (KeyError, AttributeError, TypeError):
            self.audit.emit("permit_malformed", "gatekeeper", {"agent_id": agent_id})
            raise PermitError("malformed permit")
        expected = hmac.new(
            self._secret, _canonical(body).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, str(sig)):
            self.audit.emit("permit_forgery_rejected", "gatekeeper",
                            {"agent_id": agent_id})
            raise PermitError("permit signature invalid — forgery rejected")
        if body.get("agent_id") != agent_id:
            self.audit.emit("permit_misuse_rejected", "gatekeeper",
                            {"agent_id": agent_id,
                             "reason": "permit bound to a different agent"})
            raise PermitError("permit bound to a different agent")
        if body.get("action_hash") != _action_hash(request):
            self.audit.emit("permit_misuse_rejected", "gatekeeper",
                            {"agent_id": agent_id,
                             "reason": "permit does not match this action request"})
            raise PermitError("permit does not match this action request")
        if body.get("nonce") in self._used_nonces:
            self.audit.emit("permit_replay_rejected", "gatekeeper",
                            {"agent_id": agent_id, "nonce": body.get("nonce")})
            raise PermitError("permit already used — replay rejected")
        try:
            age = time.time() - float(body.get("issued_at", 0))
        except (TypeError, ValueError):
            raise PermitError("permit has invalid issued_at")
        if age > PERMIT_TTL_SECONDS or age < -60:
            raise PermitError("permit expired")
        self._used_nonces.add(body["nonce"])
        result = handler(request)
        self.audit.emit(
            "action_executed", agent_id,
            {"action": request.get("action"),
             "action_hash": body["action_hash"]},
        )
        return result
