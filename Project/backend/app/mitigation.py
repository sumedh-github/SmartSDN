"""Mitigation request management for SOC-style IDS prototype."""

from __future__ import annotations

from collections import defaultdict
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
        self._automatic_hit_counter: dict[str, int] = defaultdict(int)
        self._automatic_last_trigger_count: dict[str, int] = defaultdict(int)

    def config(self) -> AutoMitigationConfig:
        with self._lock:
            return self._config.model_copy()

    def update_config(self, request: MitigationConfigUpdateRequest) -> AutoMitigationConfig:
        with self._lock:
            current = self._config.model_copy(update=request.model_dump(exclude_none=True))
            self._config = current
            return self._config.model_copy()

    def register_request(self, request: MitigationRequest) -> MitigationEvent:
        normalized = self._normalize_request(request)
        with self._lock:
            self._requests.append(normalized)
            now = datetime.now(timezone.utc)
            timeout_sec = normalized.timeout_sec
            if timeout_sec is None and normalized.triggered_by == "automatic":
                timeout_sec = self._config.default_timeout_sec
            expires_at = None
            if timeout_sec and timeout_sec > 0:
                expires_at = now + timedelta(seconds=timeout_sec)

            return MitigationEvent(
                mitigation_id=str(uuid4()),
                timestamp=now,
                action=normalized.action,
                target_type=self._target_type_for_action(normalized.action),
                triggered_by=normalized.triggered_by,
                reason=normalized.reason or "No reason provided.",
                status="active",
                flow_key=normalized.flow_key,
                src_ip=normalized.src_ip,
                dst_ip=normalized.dst_ip,
                protocol=normalized.protocol,
                switch_id=normalized.switch_id,
                port_id=normalized.port_id,
                target_summary=self._target_summary(normalized),
                threshold=normalized.threshold,
                condition=normalized.condition,
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

            hit_key = self._auto_hit_key(event)
            self._automatic_hit_counter[hit_key] += 1
            hit_count = self._automatic_hit_counter[hit_key]
            threshold = max(1, config.escalate_after_count)
            last_trigger_count = self._automatic_last_trigger_count[hit_key]

            # Trigger once at threshold and then once per additional threshold window.
            if hit_count < threshold:
                return False
            if (hit_count - last_trigger_count) < threshold:
                return False

            self._automatic_last_trigger_count[hit_key] = hit_count
            return True

    def auto_mitigation_request(self, event: FlowEvent) -> MitigationRequest:
        with self._lock:
            config = self._config.model_copy()
            hit_key = self._auto_hit_key(event)
            hit_count = self._automatic_hit_counter[hit_key]
        selected_action = self._select_primary_auto_action(config)
        threshold = (
            f"label in {config.suspicious_labels} and confidence >= {config.min_confidence} "
            f"(escalate_after_count={config.escalate_after_count}, primary_action={selected_action})"
        )

        if selected_action == "block_flow":
            protocol = "ALL"
            return MitigationRequest(
                flow_key=event.flow_key,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                protocol=protocol,
                switch_id=event.switch_id,
                action="block_flow",
                reason=(
                    f"Automatic mitigation for {event.prediction} (conf={event.confidence:.3f}, "
                    f"hit_count={hit_count}) with flow-pair blocking across TCP/UDP/ICMP."
                ),
                threshold=threshold,
                condition=(
                    f"label={event.prediction}, confidence={event.confidence:.3f}, hit_count={hit_count}, "
                    f"flow_pair={event.src_ip}->{event.dst_ip}, blocked_protocols=TCP/UDP/ICMP"
                ),
                timeout_sec=config.default_timeout_sec,
                triggered_by="automatic",
            )

        if selected_action == "isolate_port":
            return MitigationRequest(
                flow_key=event.flow_key,
                src_ip=None,
                dst_ip=event.dst_ip,
                protocol=None,
                switch_id=event.switch_id or "s1",
                port_id=0,
                action="isolate_port",
                reason=(
                    f"Automatic mitigation for {event.prediction} (conf={event.confidence:.3f}, "
                    f"hit_count={hit_count}) with switch isolation."
                ),
                threshold=threshold,
                condition=(
                    f"label={event.prediction}, confidence={event.confidence:.3f}, hit_count={hit_count}, "
                    f"isolate_switch={event.switch_id or 's1'}, mode=all_data_ports"
                ),
                timeout_sec=config.default_timeout_sec,
                triggered_by="automatic",
            )

        return MitigationRequest(
            flow_key=event.flow_key,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            protocol=None,
            switch_id=event.switch_id,
            action="block_source",
            reason=(
                f"Automatic mitigation for {event.prediction} (conf={event.confidence:.3f}, "
                f"hit_count={hit_count}) with source-wide IPv4 blocking."
            ),
            threshold=threshold,
            condition=(
                f"label={event.prediction}, confidence={event.confidence:.3f}, hit_count={hit_count}, "
                "blocked_protocols=TCP/UDP/ICMP"
            ),
            timeout_sec=config.default_timeout_sec,
            triggered_by="automatic",
        )

    def _select_primary_auto_action(self, config: AutoMitigationConfig) -> str:
        if config.action_order:
            return config.action_order[0]
        return "block_source"

    def _normalize_request(self, request: MitigationRequest) -> MitigationRequest:
        normalized_protocol = request.protocol.upper().strip() if request.protocol else None
        if normalized_protocol in {"ANY", "*"}:
            normalized_protocol = "ALL"
        if normalized_protocol is None and request.action == "block_flow":
            normalized_protocol = "ALL"
        normalized = request.model_copy(update={"protocol": normalized_protocol})
        if normalized.action == "block_flow":
            if not normalized.src_ip or not normalized.dst_ip:
                raise ValueError("Block Flow Pair requires src_ip and dst_ip.")
            if normalized.protocol is not None and normalized.protocol not in {"TCP", "UDP", "ICMP", "ALL"}:
                raise ValueError("Block Flow Pair protocol must be TCP, UDP, ICMP, or ALL.")
        elif normalized.action == "block_source":
            if not normalized.src_ip:
                raise ValueError("Block Source Host requires src_ip.")
        elif normalized.action == "isolate_port":
            if not normalized.switch_id:
                normalized = normalized.model_copy(update={"switch_id": "s1"})
            normalized = normalized.model_copy(update={"port_id": 0, "src_ip": None})
        return normalized

    def _target_type_for_action(self, action: str) -> str:
        if action == "block_flow":
            return "flow_pair"
        if action == "block_source":
            return "source_host"
        return "port"

    def _target_summary(self, request: MitigationRequest) -> str:
        if request.action == "block_flow":
            return f"flow_pair:{request.src_ip}->{request.dst_ip}:{request.protocol or 'ALL'}"
        if request.action == "block_source":
            return f"source_host:{request.src_ip}"
        return f"switch_isolation:{request.switch_id or 's1'}"

    def _auto_hit_key(self, event: FlowEvent) -> str:
        return f"{event.src_ip}|{event.dst_ip}|{event.protocol.upper()}"
