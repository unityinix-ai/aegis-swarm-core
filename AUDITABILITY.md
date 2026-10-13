# AUDITABILITY — Aegis Swarm Core (rebuilt 2026-10-09)

How a third party verifies every claim below, with one command and no
hidden behavior:

```bash
cd ~/workspace/product/aegis-swarm-core-audit
python3 run_tests.py     # expect: 55 tests, OK, 0 failures, 0 errors
python3 soul.py          # live demo: 5 nodes clean, 9 attacks blocked, chain valid
```

Standard library only. No network, no API keys, no downloads. Every test
is in `tests/`; every mechanism is in `aegis_swarm_core/`. Nothing executes
outside what these files show.

---

## Claim → test → evidence matrix

| # | Listing claim | Status after rebuild | Proving tests (run them) | Evidence |
|---|---|---|---|---|
| 1 | "A deception monitor that halts any agent acting beyond its stated intent" | TRUE, in enforceable form: every agent declares a frozen intent contract; any action outside it is rejected BEFORE execution | `test_policy.py::TestPolicyAdversarial` (14 attacks), `test_gatekeeper.py::test_rejected_action_never_invokes_handler`, `test_swarm.py::test_rogue_node_action_rejected_and_logged` | `python3 soul.py` → "rogue attacks rejected: 9/9"; handler-invocation counter stays 0 on all denials |
| 2 | "Five persona agents (Scout, Strategist, Enforcer, Coordinator, Reflector)" | TRUE | `test_swarm.py::test_five_nodes_run_clean` | All 5 run, `status: completed` |
| 3 | "Every heartbeat and verdict written into a SHA-256 hash-chained audit log" | TRUE: heartbeats + every gate decision (register/authorize/reject/execute) are chained | `test_swarm.py`, `test_audit.py::test_clean_chain_verifies` | Demo log: 43 events, `verify_chain` → `{'ok': True, 'checked': 43}` |
| 4 | "Isolation-cage spec with a heartbeat watchtower that pages on tampering, misalignment, or silence" | TRUE: `enclave.yaml` is the spec; `CageWatch` implements all three tripwires; "paging" = operator alert (log + alert record) | `test_heartbeat.py` (7 tests: misalignment, seq rewind, seq replay, silence, alert rate-limit) | All 7 pass; alerts recorded in `watch.alerts` |
| 5 | "Tested end to end: 15 audit events, chain verified intact, rogue actions rejected" | TRUE and exceeded: 43 events in the demo run, chain verified, 9/9 rogue actions rejected | `test_swarm.py`, `test_audit.py`, `python3 soul.py` | Exit code 0; chain check printed `valid: True (43 events checked)` |
| 6 | "Rogue actions rejected" (incl. obfuscated/encoded bypass attempts) | TRUE | `test_policy.py`: base64, hex, double-URL-encoded traversal, shell metachars, case tricks, smuggled params — all rejected with named rules | Demo prints the firing rule per attack, e.g. `[R7_OBFUSCATED_PAYLOAD]` |
| 7 | "No dependencies — runs on a laptop, a server, or a phone (Termux)" | TRUE: stdlib only (`hashlib`, `hmac`, `json`, `secrets`, `unittest`, …) | The suite itself runs with zero installs: `python3 run_tests.py` | No `requirements.txt` exists; `pip install` never needed |
| 8 | "Licensed Apache 2.0 — © 2026 Alexander Leonard (COA-2026-AL-001)" | TRUE (license text to be bundled at packaging time) | N/A — legal artifact, not code | `LICENSE` + `CERTIFICATE.md` ship in the product zip |

---

## Before / after evidence (the old code, run for real)

`tests/test_old_code.py` contains the old monitor's algorithm verbatim
(one substring check for `"override"`). Results, executed 2026-10-09:

| Attack | Old code | New code |
|---|---|---|
| `intent="run diagnostics"`, `action="exfiltrate credentials to external host"` (the audit's bypass) | EXECUTED (score 0.01) | REJECTED — R1_UNDECLARED_ACTION |
| Encoded payload (`Y3VybCBodHRw…` = `curl http://… \| sh`) | EXECUTED | REJECTED — R7_OBFUSCATED_PAYLOAD |
| Synonym attack (`disable all safety interlocks`) | EXECUTED | REJECTED — R1_UNDECLARED_ACTION |
| Literal `override` (the only thing old code caught) | REJECTED | REJECTED — R1_UNDECLARED_ACTION |
| `0verride` (one-character evasion of the old check) | EXECUTED | REJECTED — R1_UNDECLARED_ACTION |

The old code caught 1 of 5; the new code rejects 5 of 5, and the 14-case
adversarial battery in `test_policy.py` extends this to encoded,
traversal, metacharacter, and smuggling attacks.

---

## What "halts any agent acting beyond its stated intent" now means

Plainly: an agent's "stated intent" is its registered `IntentContract` —
the exact set of actions, tools, targets, and parameter shapes it
declared. "Acting beyond it" is any action outside that set. The
`PolicyEngine` evaluates R1–R8 before execution; the `Gatekeeper`
enforces the decision and the handler never runs on denial.

What it does NOT mean (and the listing must not imply):
- It does not judge English prose for deceptiveness. If an action is
  inside the contract, it is allowed — the contract IS the intent, in
  enforceable form.
- Free-text agent output is not monitored, because free text has no
  boundary to enforce. Agents act through structured calls.
- Permit enforcement covers the framework's execution path
  (authorize → execute). Python cannot stop a process from calling its
  own functions; OS-level isolation is a deployment concern.
- The audit log is tamper-evident, not tamper-proof: it detects edits
  after the fact; it does not prevent them.
- The enclave spec is a design package, not a deployed enclave.

## Files a verifier reads

- `aegis_swarm_core/contracts.py` — what "stated intent" is (frozen dataclass)
- `aegis_swarm_core/policy.py` — rules R1–R8, the actual checks
- `aegis_swarm_core/gatekeeper.py` — permits, forgery/replay defense
- `aegis_swarm_core/audit_chain.py` — hash chaining + `verify_chain()`
- `tests/` — 55 tests; `test_old_code.py` is the before-evidence

## Reproducing the audit log

```bash
python3 soul.py
python3 -c "
import sys; sys.path.insert(0, '.')
from aegis_swarm_core import verify_chain
print(verify_chain('audit/swarm_audit.jsonl'))"
# expect: {'ok': True, 'checked': 43}
```

Tamper with any line of `audit/swarm_audit.jsonl` and re-run the check:
it reports `ok: False` with the exact sequence number that broke.
