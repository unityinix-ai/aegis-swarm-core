"""Aegis Swarm Core — rebuilt deception/intent monitoring.

Public surface:
    IntentContract, ParamRule   — structured, immutable intent declarations
    PolicyEngine, Decision      — pre-execution policy checks
    Gatekeeper                  — permit-gated execution (HMAC-signed permits)
    PermitError, PolicyDenied   — failure modes
    AuditChain, verify_chain    — tamper-evident hash-chained audit log
    CageWatch                   — heartbeat watchtower logic
"""
from .contracts import IntentContract, ParamRule
from .policy import PolicyEngine, Decision
from .gatekeeper import Gatekeeper, PermitError, PolicyDenied
from .audit_chain import AuditChain, verify_chain
from .heartbeat import CageWatch

__all__ = [
    "IntentContract", "ParamRule",
    "PolicyEngine", "Decision",
    "Gatekeeper", "PermitError", "PolicyDenied",
    "AuditChain", "verify_chain",
    "CageWatch",
]
