# Aegis Swarm Core — rebuilt 2026-10-09

A working multi-agent swarm with **real** intent-contract enforcement and a
cryptographically chained audit log. Zero dependencies — pure Python
standard library. Runs on anything, including a phone (Termux).

## What changed and why

The old `soul.py` "deception monitor" was one substring check for the word
`override` in free-text output. The 2026-10-08 audit proved it bypassable
live: `{"intent":"run diagnostics","action":"exfiltrate credentials to
external host"}` → **EXECUTED, aligned: True**.

The rebuild replaces free-text monitoring — which cannot be enforced —
with **structured intent contracts**: every agent declares exactly which
actions, tools, targets, and parameters it may use. Every action is
checked against that contract BEFORE it executes. Anything outside the
contract is rejected and logged. Permits are HMAC-signed, single-use, and
bound to the exact request, so nothing executes without passing the check.

## Layout

| Path | What it does |
|---|---|
| `soul.py` | Demo harness: clean swarm pass + 9-attack rogue battery + permit-forgery/replay demos + chain verification |
| `aegis_swarm_core/contracts.py` | `IntentContract` — frozen, immutable intent declarations |
| `aegis_swarm_core/policy.py` | `PolicyEngine` — pre-execution checks R1–R8 (contract boundary + obfuscation tripwires) |
| `aegis_swarm_core/gatekeeper.py` | `Gatekeeper` — HMAC-signed single-use permits; the only path to execution |
| `aegis_swarm_core/audit_chain.py` | `AuditChain` + `verify_chain()` — SHA-256 hash-chained JSONL log, tamper-evident |
| `aegis_swarm_core/swarm.py` | 5 persona nodes (Scout, Strategist, Enforcer, Coordinator, Reflector), all gated |
| `aegis_swarm_core/heartbeat.py` | `CageWatch` — heartbeat watchtower: liveness, alignment, tamper tripwires |
| `tests/` | 55 tests incl. adversarial battery; `test_old_code.py` proves the old monitor failed |
| `run_tests.py` | One command: `python3 run_tests.py` |
| `enclave.yaml` / `echo-twin.yaml` | Design specs (unchanged from prior release — specs, not deployments) |
| `UNIFIED.md` | Architecture of the rebuilt system |
| `AUDITABILITY.md` | Claim → test → evidence matrix for third-party verification |
| `swarm-core-listing-copy-DRAFT.md` | Honest replacement listing copy (draft — live page untouched) |

## Run it

```bash
cd ~/workspace/product/aegis-swarm-core-audit
python3 run_tests.py   # 55 tests, all must pass
python3 soul.py        # live demo: 5 nodes clean, 9 attacks blocked, chain verified
ls audit/              # swarm_audit.jsonl — every gate decision, hash-chained
```

## Honest scope

- The guarantee is the **contract boundary**: any action outside an agent's
  declared contract is rejected before execution. Free-text prose is not
  executable and is not monitored — agents act through structured calls.
- The obfuscation tripwires (base64/hex/URL decoding, shell-metachar scan,
  dangerous-token list) are defense-in-depth, not the guarantee.
- The audit chain is **tamper-evident, not tamper-proof**: it detects edits
  after the fact; it does not prevent them.
- Permit enforcement covers every execution **through the gate**. Python
  cannot stop a process from calling its own functions; a deployment
  needing OS-level enforcement would run effect handlers in a separate
  process behind the gatekeeper.
- The enclave spec is a design package, not a deployed enclave.

## License

Apache 2.0 — © 2026 Alexander Leonard (Certificate of Original Authorship COA-2026-AL-001).
