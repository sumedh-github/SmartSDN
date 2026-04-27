"""Mitigation request management for SOC-style IDS prototype."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import RLock
from uuid import uuid4

from backend.app.schemas import (
    AutoMitigationConfig,
    FlowEvent,
    MitigationConfigUpdateRequest,
    MitigationEvent,
    MitigationRequest,
)


class MitigationService:
    """Maintains mitigation config and emits explainable mitigation events."""

    def __init__(self, mode: str = "IDS_ONLY") -> None:
        self.mode = mode
        self._lock = RLock()
        self._requests: list[MitigationRequest] = []
        self._config = AutoMitigationConfig()

    def config(self) -> AutoMitigationConfig:
        with self._lock:
            return self._config.model_copy()

    def update_config(self, request: MitigationConfigUpdateRequest) -> AutoMitigationConfig:
        with self._lock:
            current = self._config.model_copy(update=request.model_dump(exclude_none=True))
            self._config = current
            return self._config.model_copy()

    def register_request(self, request: MitigationRequest) -> MitigationEvent:
        with self._lock:
            self._requests.append(request)
            now = datetime.now(timezone.utc)
            timeout_sec = request.timeout_sec
            if timeout_sec is None and request.triggered_by == "automatic":
                timeout_sec = self._config.default_timeout_sec
            expires_at = None
            if timeout_sec and timeout_sec > 0:
                expires_at = now + timedelta(seconds=timeout_sec)

            return MitigationEvent(
                mitigation_id=str(uuid4()),
                timestamp=now,
                action=request.action,
                triggered_by=request.triggered_by,
                reason=request.reason or "No reason provided.",
                status="active",
                flow_key=request.flow_key,
                src_ip=request.src_ip,
                dst_ip=request.dst_ip,
                switch_id=request.switch_id,
                port_id=request.port_id,
                expires_at=expires_at,
            )

    def should_auto_mitigate(self, event: FlowEvent) -> bool:
        with self._lock:
            config = self._config.model_copy()

        if not config.enabled:
            return False
        if event.prediction not in config.suspicious_labels:
            return False
        if event.confidence < config.min_confidence:
            return False
        return True

    def auto_mitigation_request(self, event: FlowEvent) -> MitigationRequest:
        with self._lock:
            config = self._config.model_copy()
        action = config.action_order[0] if config.action_order else "block_flow"
        return MitigationRequest(
            flow_key=event.flow_key,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            switch_id=event.switch_id,
            action=action,
            reason=f"Automatic mitigation for {event.prediction} (conf={event.confidence:.3f})",
            timeout_sec=config.default_timeout_sec,
            triggered_by="automatic",
        )
