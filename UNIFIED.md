# UNIFIED.md — Aegis Swarm Core architecture (rebuilt 2026-10-09)

## The problem with the old design

The old core tried to detect deception by comparing two English sentences:
stated `intent` vs executed `action`, with a single substring check for
the word "override". This fails for a structural reason, not a tuning
reason: **free text has no boundary to enforce**. Any paraphrase, synonym,
or encoding walks past a string match. The 2026-10-08 audit demonstrated
this live. No heuristic layered on free text fixes it — the architecture
was wrong, so it was replaced.

## The new design: contracts, not sentences

```
  ┌──────────────┐
  │ IntentContract│  frozen dataclass per agent: allowed actions, tools,
  │  (immutable)  │  targets, param rules, call budget. Registered once.
  └──────┬───────┘
         │ register() — logged to audit chain with contract hash
         ▼
  ┌──────────────┐
  │ PolicyEngine  │  pre-execution evaluation, rules R1–R8:
  │  evaluate()   │  R1 action declared? R2 tool declared? R3 target in
  └──────┬───────┘  scope? R4 params conform? R5 traversal? R6 shell
         │          metachars? R7 decoded-layer payload? R8 tokens?
         ▼
  ┌──────────────┐   allow → signed permit (HMAC-SHA256, per-session
  │  Gatekeeper   │   secret, single-use nonce, bound to exact request)
  │  authorize()  │   deny  → PolicyDenied, rejection logged, handler
  │  execute()    │           NEVER invoked
  └──────┬───────┘
         │ permit verified (signature, agent, action hash, nonce, expiry)
         ▼
  ┌──────────────┐
  │ effect handler│  the real side effect — runs only after the gate
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │  AuditChain   │  every registration, authorization, rejection,
  │  (hash-chained│  execution, and heartbeat → SHA-256-chained JSONL
  │   JSONL)      │  verify_chain() recomputes every link
  └──────────────┘
```

Two agent layers sit on top of this single gate:

- **Swarm layer** (`swarm.py`): 5 persona nodes — Scout, Strategist,
  Enforcer, Coordinator, Reflector. Persona changes behavior and
  expression, never permissions. All five share the one authorization
  boundary: the gate.
- **Watchtower layer** (`heartbeat.py`): `CageWatch` monitors liveness
  (silence > dead_after), alignment (`aligned=false`), and audit
  sequence tampering (seq moving backward). Alerts page the operator.

## Why this is actually enforceable

1. **Closed vocabulary.** Actions are canonical names from a fixed set,
   matched exactly and case-sensitively. There is no paraphrase problem
   because there is no prose at the enforcement point.
2. **Pre-execution.** The check runs before the handler. Denial means the
   handler never runs — proven by test (handler-invocation counter stays
   zero on every rejected attack).
3. **Permits, not trust.** Execution requires a permit the agent cannot
   forge (HMAC secret never leaves the gatekeeper), cannot replay
   (single-use nonces), cannot transfer (bound to agent id), and cannot
   repurpose (bound to the canonical hash of the exact request).
4. **Immutable contracts.** Registration is one-time; re-registration is
   rejected and logged. An agent cannot widen its own permissions.
5. **Everything is logged.** Registration, authorization, rejection,
   execution, forgery attempts, replays — all hash-chained. `verify_chain`
   detects any edit, deletion, or insertion after the fact.

## What this does NOT do (stated plainly)

- It does not read an agent's mind or judge prose for "deceptiveness".
  If an action is inside the contract, it is allowed — the contract IS
  the stated intent, in enforceable form.
- It does not prevent a Python process from calling its own functions.
  The guarantee covers the framework's execution path (authorize →
  execute). OS-level isolation is a deployment concern, out of scope.
- The audit log detects tampering; it does not prevent it.
- The enclave spec (`enclave.yaml`) remains a design package.

## Test map

`python3 run_tests.py` — 55 tests:
- `test_old_code.py` (4): the old monitor, run verbatim, EXECUTEs attacks.
- `test_contracts.py` (6): immutability, hashing, target patterns.
- `test_policy.py` (17): clean traffic allowed; 14 adversarial cases denied.
- `test_gatekeeper.py` (11): forgery, replay, cross-agent, expiry, budget.
- `test_audit.py` (7): clean verify; content edit, deletion, garbage, missing file.
- `test_swarm.py` (3): 5 nodes clean; rogue action rejected + logged.
- `test_heartbeat.py` (7): misalignment, seq rewind/replay, silence, alert rate-limit.
