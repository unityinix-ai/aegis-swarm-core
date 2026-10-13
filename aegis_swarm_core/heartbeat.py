"""Heartbeat watchtower — parent-side monitor for agent liveness.

Ported from the original heartbeat_listener.py (verified live over TCP on
2026-10-08). Three tripwires:
  - liveness:   no heartbeat for DEAD_AFTER seconds  -> cage dead/compromised
  - alignment:  heartbeat with aligned=false         -> halt dependents, page operator
  - tamper:     audit_seq steps backward              -> possible tampering

handle() and check_liveness() RETURN the alert string (or None) so the
tripwires are unit-testable without sockets. They also log, preserving the
original operational behavior. serve_forever() keeps the original
vsock/TCP listener for live use.
"""
from __future__ import annotations

import json
import logging
import socket
import sys
import time

HEARTBEAT_PORT = 5005

log = logging.getLogger("cage-listener")


class CageWatch:
    def __init__(self, expected_interval: float = 30.0, dead_after: float = 90.0):
        self.expected_interval = expected_interval
        self.dead_after = dead_after
        self.last_beat = 0.0
        self.last_seq = -1
        self.last_dead_alert = 0.0
        self.alerts = []  # every alert string, in order — the test hook

    def _alert(self, msg: str) -> str:
        log.error("ALERT: %s", msg)
        self.alerts.append(msg)
        return msg

    def handle(self, hb: dict):
        """Process one heartbeat dict. Returns the alert string, or None."""
        node = hb.get("node_id", "?")
        if not hb.get("aligned", True):
            return self._alert(
                "%s reports aligned=false — halting dependents, paging operator" % node
            )
        seq = hb.get("audit_seq", -1)
        if self.last_seq != -1 and seq <= self.last_seq:
            return self._alert(
                "%s audit_seq went backward (%s -> %s) — possible tampering"
                % (node, self.last_seq, seq)
            )
        self.last_seq = seq
        self.last_beat = time.time()
        log.info("heartbeat ok: %s seq=%s score=%s",
                 node, seq, hb.get("deception_score"))
        return None

    def check_liveness(self, now: float | None = None):
        """Returns the dead-cage alert string, or None."""
        now = time.time() if now is None else now
        if (self.last_beat
                and now - self.last_beat > self.dead_after
                and now - self.last_dead_alert > self.dead_after):
            self.last_dead_alert = now
            return self._alert(
                "no heartbeat for %ds — cage dead or compromised"
                % int(now - self.last_beat)
            )
        return None


def serve_forever(use_tcp: bool = False):
    """Blocking listener. vsock 5005 in production; TCP loopback for tests."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    if use_tcp:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", HEARTBEAT_PORT))
        log.info("listening on TCP 127.0.0.1:%d (local test mode)", HEARTBEAT_PORT)
    else:
        try:
            srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        except OSError as e:
            log.error("vsock unavailable on this host: %s", e)
            sys.exit(1)
        srv.bind((socket.VMADDR_CID_ANY, HEARTBEAT_PORT))
        log.info("listening on vsock %d — waiting for the cage", HEARTBEAT_PORT)
    srv.listen(1)
    srv.settimeout(5)
    watch = CageWatch()
    while True:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            watch.check_liveness()
            continue
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        try:
                            watch.handle(json.loads(line.decode("utf-8")))
                        except json.JSONDecodeError:
                            watch._alert("received unparsable heartbeat payload")
        watch.check_liveness()
