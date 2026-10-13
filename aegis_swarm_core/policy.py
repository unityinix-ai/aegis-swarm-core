"""Pre-execution policy engine.

An action is a structured request::

    {
        "agent_id": "node-scout",
        "action":   "scan_sector",      # canonical name, case-sensitive
        "tool":     "telemetry",
        "target":   "sector:7g",
        "params":   {"depth": 3},
    }

evaluate(contract, request) -> Decision. The action is allowed ONLY when
no rule fires. Every denial names the rule(s) that fired, and the denial
is what the Gatekeeper logs.

Rule IDs:
  R1_UNDECLARED_ACTION   action not in contract.allowed_actions
  R2_UNDECLARED_TOOL     tool not in contract.allowed_tools
  R3_UNDECLARED_TARGET   target matches no allowed target pattern
  R4_PARAM_VIOLATION     unknown param / wrong type / too long / pattern mismatch
  R5_PATH_TRAVERSAL      ".." segment smuggled into a string parameter
  R6_SHELL_METACHAR      shell metacharacter in a non-shell string parameter
  R7_OBFUSCATED_PAYLOAD  a decoded layer of a parameter hides dangerous content
  R8_DANGEROUS_TOKEN     dangerous token in a raw parameter value

R1-R4 are the HARD GUARANTEE (the contract boundary). R5-R8 are
defense-in-depth tripwires against smuggling hostile content through a
declared action. The tripwires do not replace the boundary.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

# Metacharacters that have no business in a plain data parameter.
SHELL_METACHARS = frozenset({";", "|", "&", "$", "`", ">", "<", "\n", "\r", "\x00"})

# High-signal dangerous tokens. Kept deliberately narrow to avoid false
# positives on ordinary parameter values; the contract boundary (R1-R4)
# is the guarantee, this list is the tripwire.
DANGEROUS_TOKENS = (
    "rm -rf", "rm -fr", "mkfs", "dd if=", ":(){",
    "chmod ", "chown ",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", ".ssh/",
    "curl ", "wget ", "ftp ", "nc ", "ncat", "netcat", "telnet ",
    "powershell", "invoke-expression", "cmd /c", "/bin/sh", "/bin/bash",
    "sudo ", "passwd ", "ssh ", "scp ", "rsync ",
    "exfiltrate", "exfiltration", "credential",
    "api_key", "apikey", "secret_key", "private_key", "privatekey",
    "http://", "https://",
    "| sh", "| bash", "base64 -d", "base64 --decode",
)


@dataclass
class Decision:
    allowed: bool
    violations: list = field(default_factory=list)  # [(rule_id, message)]

    def __bool__(self):
        return self.allowed


def _decode_layers(value: str):
    """Yield (layer_name, decoded_text) for each successful decoding.

    Catches URL-encoding (single and double), base64, and hex wrappers
    used to smuggle hostile content past naive string matching.
    """
    layers = []
    cur = value
    for i in (1, 2):
        try:
            nxt = unquote(cur)
        except Exception:
            break
        if nxt != cur:
            layers.append(("urldecode-x%d" % i, nxt))
            cur = nxt
        else:
            break
    s = re.sub(r"\s+", "", value)
    if len(s) >= 16 and len(s) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        try:
            txt = base64.b64decode(s, validate=True).decode("utf-8")
            if txt != value:
                layers.append(("base64", txt))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    if len(s) >= 16 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        try:
            txt = bytes.fromhex(s).decode("utf-8")
            if txt != value:
                layers.append(("hex", txt))
        except (ValueError, UnicodeDecodeError):
            pass
    return layers


def _scan_text(text: str):
    """Return [(kind, token)] hits: dangerous tokens + shell metachars."""
    hits = []
    low = text.lower()
    for tok in DANGEROUS_TOKENS:
        if tok in low:
            hits.append(("dangerous-token", tok))
    for ch in SHELL_METACHARS:
        if ch in text:
            hits.append(("shell-metachar", repr(ch)))
    return hits


class PolicyEngine:
    def evaluate(self, contract, request: dict) -> Decision:
        violations = []
        agent = request.get("agent_id", "?")
        action = request.get("action")
        tool = request.get("tool")
        target = request.get("target")
        params = request.get("params", {})

        # R1 — the action must be declared.
        if action not in contract.allowed_actions:
            violations.append((
                "R1_UNDECLARED_ACTION",
                "action %r not in contract for %s" % (action, agent),
            ))
        # R2 — the tool must be declared.
        if tool not in contract.allowed_tools:
            violations.append((
                "R2_UNDECLARED_TOOL",
                "tool %r not in contract for %s" % (tool, agent),
            ))
        # R3 — the target must match a declared pattern.
        if not contract.target_allowed(target or ""):
            violations.append((
                "R3_UNDECLARED_TARGET",
                "target %r matches no allowed target for %s" % (target, agent),
            ))
        # R4 — parameters must conform to the declared rules.
        rules = contract.param_rules.get(action, {})
        if not isinstance(params, dict):
            violations.append(("R4_PARAM_VIOLATION", "params must be an object"))
            params = {}
        else:
            for name, value in params.items():
                rule = rules.get(name)
                if rule is None:
                    violations.append((
                        "R4_PARAM_VIOLATION",
                        "undeclared param %r for action %r" % (name, action),
                    ))
                    continue
                violations.extend(self._check_param(action, name, value, rule))

        # R5-R8 — content tripwires over every string parameter.
        if isinstance(params, dict):
            for name, value in params.items():
                rule = rules.get(name)
                if not isinstance(value, str):
                    continue
                allow_shell = bool(rule and rule.allow_shell)
                # R5 — path traversal (".." as a path segment).
                if re.search(r"(^|[/\\])\.\.([/\\]|$)", value):
                    violations.append((
                        "R5_PATH_TRAVERSAL",
                        "param %r contains '..' path traversal" % name,
                    ))
                # R6 — shell metacharacters in non-shell params.
                if not allow_shell:
                    for ch in SHELL_METACHARS:
                        if ch in value:
                            violations.append((
                                "R6_SHELL_METACHAR",
                                "param %r contains shell metacharacter %r" % (name, ch),
                            ))
                            break
                # R8 — dangerous tokens in the raw value.
                low = value.lower()
                for tok in DANGEROUS_TOKENS:
                    if tok in low:
                        violations.append((
                            "R8_DANGEROUS_TOKEN",
                            "param %r contains dangerous token %r" % (name, tok),
                        ))
                        break
                # R7 — decode every layer; hostile content hiding inside
                # an encoding is still hostile content.
                for layer_name, decoded in _decode_layers(value):
                    fired = False
                    for kind, token in _scan_text(decoded):
                        violations.append((
                            "R7_OBFUSCATED_PAYLOAD",
                            "param %r hides %s %r inside %s encoding"
                            % (name, kind, token, layer_name),
                        ))
                        fired = True
                        break
                    if not fired and re.search(r"(^|[/\\])\.\.([/\\]|$)", decoded):
                        violations.append((
                            "R7_OBFUSCATED_PAYLOAD",
                            "param %r hides path traversal inside %s encoding"
                            % (name, layer_name),
                        ))

        return Decision(allowed=not violations, violations=violations)

    def _check_param(self, action, name, value, rule):
        problems = []
        ptype = rule.ptype
        if ptype == "string":
            if not isinstance(value, str):
                problems.append(("R4_PARAM_VIOLATION",
                                 "param %r must be a string" % name))
            else:
                if len(value) > rule.max_len:
                    problems.append(("R4_PARAM_VIOLATION",
                                     "param %r exceeds max_len %d" % (name, rule.max_len)))
                if rule.pattern is not None and not re.fullmatch(rule.pattern, value):
                    problems.append(("R4_PARAM_VIOLATION",
                                     "param %r fails pattern %r" % (name, rule.pattern)))
        elif ptype == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(("R4_PARAM_VIOLATION",
                                 "param %r must be an integer" % name))
        elif ptype == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                problems.append(("R4_PARAM_VIOLATION",
                                 "param %r must be a number" % name))
        elif ptype == "boolean":
            if not isinstance(value, bool):
                problems.append(("R4_PARAM_VIOLATION",
                                 "param %r must be a boolean" % name))
        else:
            problems.append(("R4_PARAM_VIOLATION",
                             "unknown param type %r for %r" % (ptype, name)))
        return problems
