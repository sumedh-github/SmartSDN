"""Mitigation service stubs for future IPS extensions."""

from __future__ import annotations

from threading import RLock

from backend.app.schemas import MitigationRequest


class MitigationService:
    """Records mitigation requests while staying IDS-only by default."""

    def __init__(self, mode: str = "IDS_ONLY") -> None:
        self.mode = mode
        self._lock = RLock()
        self._requests: list[MitigationRequest] = []

    def register_request(self, request: MitigationRequest) -> dict[str, str]:
        with self._lock:
            self._requests.append(request)

        return {
            "status": "accepted",
            "mode": self.mode,
            "message": (
                "Mitigation request recorded, but enforcement is disabled in IDS-only mode."
            ),
        }
