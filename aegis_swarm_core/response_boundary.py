"""Commit-before-release boundary for seat responses."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, json, threading, uuid
from typing import Callable
from .audit_chain import AuditChain, verify_chain


class ResponseBoundaryError(RuntimeError):
    """A response could not be safely sealed; caller must withhold it."""


class SeatCallError(ResponseBoundaryError):
    """The seat failed before producing a successful response."""


@dataclass(frozen=True)
class SealedSeatResponse:
    response_id: str
    sequence: int
    record_hash: str
    seat_name: str
    task_id: str
    prompt_hash: str
    response_hash: str
    output: str
    verdict: str = "UNVERIFIABLE"


class SeatResponseAdapter:
    """Seal and verify successful seat output before returning it.

    Use one adapter and one AuditChain writer per file. Independent concurrent
    writers are unsupported. The chain is tamper-evident, not tamper-proof.
    """
    def __init__(self, audit: AuditChain):
        self.audit = audit
        self._lock = threading.RLock()

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _verify_writer_state(self) -> dict:
        result = verify_chain(self.audit.path)
        if not result.get("ok"):
            raise ResponseBoundaryError("Existing audit chain failed verification: %s" % result)
        count = result.get("checked", 0)
        if count != self.audit.event_count:
            raise ResponseBoundaryError("Audit writer is stale: event count does not match file")
        if count:
            try:
                with open(self.audit.path, "r", encoding="utf-8") as handle:
                    lines = [line for line in handle if line.strip()]
                head = json.loads(lines[-1]).get("hash")
            except (OSError, ValueError, IndexError) as exc:
                raise ResponseBoundaryError("Could not inspect audit-chain head") from exc
            if head != self.audit.prev_hash:
                raise ResponseBoundaryError("Audit writer head does not match file head")
        return result

    def execute(self, *, seat_name: str, task_id: str, prompt: str,
                seat_call: Callable[[str], str],
                response_id: str | None = None) -> SealedSeatResponse:
        if not seat_name or not seat_name.strip():
            raise ValueError("seat_name is required")
        if not task_id or not task_id.strip():
            raise ValueError("task_id is required")
        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")
        if not callable(seat_call):
            raise TypeError("seat_call must be callable")
        response_id = response_id or str(uuid.uuid4())

        with self._lock:
            self._verify_writer_state()  # fail closed before dispatch
            try:
                output = seat_call(prompt)
            except Exception as exc:
                raise SeatCallError("%s failed before producing a response" % seat_name) from exc
            if not isinstance(output, str):
                raise SeatCallError("seat output must be a string")

            prompt_hash = self._sha256(prompt)
            response_hash = self._sha256(output)
            event = self.audit.emit(
                "seat_response_sealed", "seat:%s" % seat_name,
                {
                    "response_id": response_id, "task_id": task_id,
                    "prompt_sha256": prompt_hash,
                    "response_sha256": response_hash,
                    "claim": output, "verdict": "UNVERIFIABLE",
                },
            )
            try:
                self.audit.flush(durable=True)
                verified = self._verify_writer_state()
            except Exception as exc:
                raise ResponseBoundaryError(
                    "Response could not be durably verified; response withheld"
                ) from exc
            if not verified.get("ok") or event.get("hash") != self.audit.prev_hash:
                raise ResponseBoundaryError("Post-append verification failed; response withheld")
            return SealedSeatResponse(
                response_id=response_id, sequence=event["seq"],
                record_hash=event["hash"], seat_name=seat_name,
                task_id=task_id, prompt_hash=prompt_hash,
                response_hash=response_hash, output=output,
            )
