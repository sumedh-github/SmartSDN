"""In-memory store for live flow, topology, and controller visibility."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from threading import RLock
from typing import Callable

from backend.app.schemas import (
    AlertReviewRequest,
    ControllerStatusPayload,
    ControllerStatusResponse,
    FlowEvent,
    LabelSource,
    MitigationEvent,
    SessionView,
    TopologyLink,
    TopologyNode,
    TopologyResponse,
    TopologyTrafficEdge,
)

CONTROLLER_NODE_ID = "controller-main"
CONTROLLER_NODE_LABEL = "Ryu IDS Controller"


def _is_suspicious(prediction: str) -> bool:
    return prediction.strip().lower() != "normal"


def _host_node_id(ip: str) -> str:
    return f"host-{ip.replace('.', '-')}"


def _pick_dominant(counter: Counter[str], fallback: str) -> str:
    if not counter:
        return fallback
    ordered = sorted(
        counter.items(),
        key=lambda item: (item[1], item[0].lower() != "normal", item[0]),
        reverse=True,
    )
    return ordered[0][0]


class EventStore:
    """Thread-safe storage for live dashboard state."""

    def __init__(self, max_events: int = 5000, max_mitigation_events: int = 2000) -> None:
        self._lock = RLock()
        self._events: list[FlowEvent] = []
        self._max_events = max_events
        self._controller_status: ControllerStatusPayload | None = None
        self._mitigation_events: list[MitigationEvent] = []
        self._active_mitigations: dict[str, MitigationEvent] = {}
        self._max_mitigation_events = max_mitigation_events

    def add_event(self, event: FlowEvent) -> FlowEvent:
        with self._lock:
            stored_event = event.model_copy()
            stored_event.mitigation_state = self._resolve_mitigation_state_locked(stored_event)
            self._events.append(stored_event)
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events :]
            return stored_event

    def upsert_controller_status(self, status: ControllerStatusPayload) -> None:
        with self._lock:
            self._controller_status = status

    def controller_status(self, stale_after_seconds: int = 10) -> ControllerStatusResponse:
        with self._lock:
            current = self._controller_status
        if current is None:
            return ControllerStatusResponse(
                timestamp=datetime.now(timezone.utc),
                running=False,
                polling_active=False,
                model_loaded=False,
                mode="REAL_ML",
                datapath_count=0,
                backend_events_url=None,
                stale=True,
            )

        age_seconds = (datetime.now(timezone.utc) - current.timestamp).total_seconds()
        stale = age_seconds > stale_after_seconds
        return ControllerStatusResponse(**current.model_dump(), stale=stale)

    def register_mitigation(self, mitigation_event: MitigationEvent) -> None:
        with self._lock:
            self._mitigation_events.append(mitigation_event)
            if len(self._mitigation_events) > self._max_mitigation_events:
                self._mitigation_events = self._mitigation_events[-self._max_mitigation_events :]
            if mitigation_event.status == "active":
                self._active_mitigations[mitigation_event.mitigation_id] = mitigation_event
            elif mitigation_event.status in {"retracted", "failed", "expired"}:
                self._active_mitigations.pop(mitigation_event.mitigation_id, None)
            self._cleanup_expired_mitigations_locked()
            self._apply_mitigation_to_existing_events_locked(mitigation_event)

    def list_mitigation_events(self, limit: int = 200) -> list[MitigationEvent]:
        with self._lock:
            self._cleanup_expired_mitigations_locked()
            return list(reversed(self._mitigation_events[-limit:]))

    def list_active_mitigations(self) -> list[MitigationEvent]:
        with self._lock:
            self._cleanup_expired_mitigations_locked()
            return list(reversed(list(self._active_mitigations.values())))

    def get_mitigation(self, mitigation_id: str) -> MitigationEvent | None:
        with self._lock:
            for event in reversed(self._mitigation_events):
                if event.mitigation_id == mitigation_id:
                    return event
        return None

    def update_mitigation(self, mitigation_event: MitigationEvent) -> MitigationEvent:
        with self._lock:
            for index, existing in enumerate(self._mitigation_events):
                if existing.mitigation_id == mitigation_event.mitigation_id:
                    self._mitigation_events[index] = mitigation_event
                    break
            if mitigation_event.status == "active":
                self._active_mitigations[mitigation_event.mitigation_id] = mitigation_event
            else:
                self._active_mitigations.pop(mitigation_event.mitigation_id, None)
            self._recompute_event_mitigation_state_locked()
            return mitigation_event

    def total_flows(self) -> int:
        with self._lock:
            return len(self._events)

    def list_flows(self, limit: int = 200) -> list[FlowEvent]:
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def list_alerts(self, limit: int = 200) -> list[FlowEvent]:
        with self._lock:
            alerts = [event for event in self._events if _is_suspicious(event.prediction)]
        return list(reversed(alerts[-limit:]))

    def mark_alert_as_normal(self, request: AlertReviewRequest) -> FlowEvent:
        with self._lock:
            for index in range(len(self._events) - 1, -1, -1):
                event = self._events[index]
                if (
                    event.timestamp == request.timestamp
                    and event.src_ip == request.src_ip
                    and event.dst_ip == request.dst_ip
                    and event.protocol.upper() == request.protocol.upper()
                ):
                    updated = event.model_copy(
                        update={
                            "prediction": "Normal",
                            "classification_source": "hybrid",
                            "notes": (
                                f"Alert marked as false positive by operator at "
                                f"{datetime.now(timezone.utc).isoformat()}."
                            ),
                        }
                    )
                    self._events[index] = updated
                    return updated
        raise ValueError("Alert event not found for false-positive review.")

    def list_sessions(self, limit: int = 500) -> list[SessionView]:
        with self._lock:
            grouped: dict[str, list[FlowEvent]] = defaultdict(list)
            for event in self._events:
                endpoint_a, endpoint_b = sorted([event.src_ip, event.dst_ip])
                session_id = f"{event.protocol}|{endpoint_a}|{endpoint_b}"
                grouped[session_id].append(event)

        sessions: list[SessionView] = []
        for session_id, records in grouped.items():
            label_counter = Counter(record.prediction for record in records)
            source_counter = Counter(record.classification_source for record in records)
            dominant_label = _pick_dominant(label_counter, fallback="Unknown")
            dominant_source = _pick_dominant(source_counter, fallback="ml")

            latest_seen = max(record.timestamp for record in records)
            confidence_values = [record.confidence for record in records]
            total_packets = sum(record.packet_count for record in records)
            total_bytes = sum(record.byte_count for record in records)

            if any(record.mitigation_state == "blocked" for record in records):
                mitigation_state = "blocked"
            elif any(record.mitigation_state != "none" for record in records):
                mitigation_state = "active"
            else:
                mitigation_state = "none"

            endpoints = sorted({records[0].src_ip, records[0].dst_ip})
            sessions.append(
                SessionView(
                    session_id=session_id,
                    source_entity=records[-1].src_ip,
                    destination_entity=records[-1].dst_ip,
                    protocol=records[0].protocol,
                    endpoints=endpoints,
                    participants=endpoints,
                    flow_count=len(records),
                    dominant_label=dominant_label,
                    dominant_label_source=dominant_source,
                    confidence_avg=sum(confidence_values) / max(1, len(confidence_values)),
                    confidence_max=max(confidence_values),
                    suspicious=_is_suspicious(dominant_label),
                    mitigation_state=mitigation_state,
                    latest_seen=latest_seen,
                    total_packets=total_packets,
                    total_bytes=total_bytes,
                )
            )

        sessions.sort(key=lambda session: session.latest_seen, reverse=True)
        return sessions[:limit]

    def topology(self) -> TopologyResponse:
        with self._lock:
            events = list(self._events)
            active_mitigations = list(self._active_mitigations.values())
        controller_status = self.controller_status()

        switch_ids = sorted({event.switch_id or "s1" for event in events} or {"s1"})
        nodes: list[TopologyNode] = [
            TopologyNode(
                id=CONTROLLER_NODE_ID,
                kind="controller",
                label=CONTROLLER_NODE_LABEL,
                status="running" if controller_status.running and not controller_status.stale else "disconnected",
                metadata={
                    "polling_active": controller_status.polling_active,
                    "model_loaded": controller_status.model_loaded,
                    "mode": controller_status.mode,
                    "datapath_count": controller_status.datapath_count,
                    "stale": controller_status.stale,
                },
            )
        ]

        for switch_id in switch_ids:
            nodes.append(
                TopologyNode(
                    id=switch_id,
                    kind="switch",
                    label=switch_id,
                    status="active" if events else "idle",
                    metadata={},
                )
            )

        host_ips = sorted({event.src_ip for event in events} | {event.dst_ip for event in events})
        blocked_sources = {mitigation.src_ip for mitigation in active_mitigations if mitigation.action == "block_source"}
        for ip in host_ips:
            nodes.append(
                TopologyNode(
                    id=_host_node_id(ip),
                    kind="host",
                    label=ip,
                    status="mitigated" if ip in blocked_sources else "active",
                    metadata={"ip": ip},
                )
            )

        links: list[TopologyLink] = []
        for switch_id in switch_ids:
            links.append(
                TopologyLink(
                    id=f"{CONTROLLER_NODE_ID}--{switch_id}",
                    source=CONTROLLER_NODE_ID,
                    target=switch_id,
                    state="normal" if controller_status.running else "idle",
                    flow_count=0,
                    packet_count=0,
                    byte_count=0,
                )
            )

        isolated_switches = {
            mitigation.switch_id or "s1"
            for mitigation in active_mitigations
            if mitigation.action == "isolate_port" and mitigation.src_ip is None
        }
        isolated_host_pairs = {
            ((mitigation.switch_id or "s1"), mitigation.src_ip)
            for mitigation in active_mitigations
            if mitigation.action == "isolate_port" and mitigation.src_ip is not None
        }

        host_link_stats: dict[tuple[str, str], dict[str, int | str]] = {}
        for event in events:
            switch_id = event.switch_id or "s1"
            for ip in (event.src_ip, event.dst_ip):
                host_id = _host_node_id(ip)
                key = (switch_id, host_id)
                if key not in host_link_stats:
                    host_link_stats[key] = {
                        "state": "idle",
                        "flow_count": 0,
                        "packet_count": 0,
                        "byte_count": 0,
                    }
                stats = host_link_stats[key]
                stats["flow_count"] = int(stats["flow_count"]) + 1
                stats["packet_count"] = int(stats["packet_count"]) + event.packet_count
                stats["byte_count"] = int(stats["byte_count"]) + event.byte_count
                if switch_id in isolated_switches or (switch_id, ip) in isolated_host_pairs:
                    stats["state"] = "disabled"
                elif event.mitigation_state == "blocked":
                    stats["state"] = "blocked"
                elif _is_suspicious(event.prediction) and stats["state"] != "blocked":
                    stats["state"] = "suspicious"
                elif stats["state"] == "idle":
                    stats["state"] = "normal"

        for (switch_id, host_id), stats in host_link_stats.items():
            links.append(
                TopologyLink(
                    id=f"{switch_id}--{host_id}",
                    source=switch_id,
                    target=host_id,
                    state=stats["state"],
                    flow_count=int(stats["flow_count"]),
                    packet_count=int(stats["packet_count"]),
                    byte_count=int(stats["byte_count"]),
                )
            )

        edge_groups: dict[str, list[FlowEvent]] = defaultdict(list)
        for event in events:
            src = _host_node_id(event.src_ip)
            dst = _host_node_id(event.dst_ip)
            edge_groups[f"{src}->{dst}|{event.protocol}"].append(event)

        traffic_edges: list[TopologyTrafficEdge] = []
        for edge_id, records in edge_groups.items():
            prediction_counter = Counter(record.prediction for record in records)
            source_counter = Counter(record.classification_source for record in records)
            dominant_label = _pick_dominant(prediction_counter, fallback="Normal")
            source = records[0]
            if any(record.mitigation_state == "blocked" for record in records):
                state = "blocked"
            elif _is_suspicious(dominant_label):
                state = "suspicious"
            else:
                state = "normal"
            traffic_edges.append(
                TopologyTrafficEdge(
                    id=edge_id,
                    source=_host_node_id(source.src_ip),
                    target=_host_node_id(source.dst_ip),
                    state=state,
                    dominant_label=dominant_label,
                    confidence=max(record.confidence for record in records),
                    classification_source=_pick_dominant(source_counter, fallback="ml"),
                    flow_count=len(records),
                )
            )

        return TopologyResponse(
            generated_at=datetime.now(timezone.utc),
            nodes=nodes,
            links=links,
            traffic_edges=traffic_edges,
        )

    def stats(self) -> dict[str, object]:
        with self._lock:
            events = list(self._events)

        class_distribution = Counter(event.prediction for event in events)
        by_source = Counter(event.classification_source for event in events)
        normal_flows = class_distribution.get("Normal", 0)
        total_flows = len(events)
        suspicious_flows = total_flows - normal_flows
        active_hosts = len({event.src_ip for event in events} | {event.dst_ip for event in events})
        mitigated_flows = sum(1 for event in events if event.mitigation_state != "none")

        return {
            "total_flows": total_flows,
            "normal_flows": normal_flows,
            "suspicious_flows": suspicious_flows,
            "active_hosts": active_hosts,
            "class_distribution": dict(sorted(class_distribution.items())),
            "by_source": dict(sorted(by_source.items())),
            "mitigated_flows": mitigated_flows,
        }

    def clear_demo_events(self) -> int:
        with self._lock:
            original = len(self._events)
            self._events = [event for event in self._events if event.event_source != "scenario_runner"]
            return original - len(self._events)

    def system_health(
        self,
        *,
        mode: str,
        mitigation_automatic_enabled: bool,
    ) -> dict[str, object]:
        controller = self.controller_status()
        topology = self.topology()
        return {
            "backend": "ok",
            "controller": "ok" if controller.running and not controller.stale else "degraded",
            "topology": "ok" if len(topology.nodes) > 0 else "empty",
            "live_event_stream": "active" if self.total_flows() > 0 else "idle",
            "mode": mode,
            "mitigation_automatic_enabled": mitigation_automatic_enabled,
        }

    def with_events(self, callback: Callable[[list[FlowEvent]], None]) -> None:
        with self._lock:
            callback(self._events)

    def _cleanup_expired_mitigations_locked(self) -> None:
        now = datetime.now(timezone.utc)
        expired_ids = [
            mitigation_id
            for mitigation_id, mitigation in self._active_mitigations.items()
            if mitigation.expires_at is not None and mitigation.expires_at <= now
        ]
        for mitigation_id in expired_ids:
            mitigation = self._active_mitigations.pop(mitigation_id)
            mitigation.status = "expired"
        if expired_ids:
            self._recompute_event_mitigation_state_locked()

    def _apply_mitigation_to_existing_events_locked(self, mitigation_event: MitigationEvent) -> None:
        for event in self._events:
            if mitigation_event.status == "active" and self._event_matches_mitigation(event, mitigation_event):
                event.mitigation_state = "blocked"

    def _resolve_mitigation_state_locked(self, event: FlowEvent) -> str:
        self._cleanup_expired_mitigations_locked()
        for mitigation in self._active_mitigations.values():
            if self._event_matches_mitigation(event, mitigation):
                return "blocked"
        return "none"

    def _recompute_event_mitigation_state_locked(self) -> None:
        for event in self._events:
            event.mitigation_state = self._resolve_mitigation_state_locked(event)

    def _event_matches_mitigation(self, event: FlowEvent, mitigation: MitigationEvent) -> bool:
        if mitigation.action == "block_flow":
            src_match = mitigation.src_ip is None or event.src_ip == mitigation.src_ip
            dst_match = mitigation.dst_ip is None or event.dst_ip == mitigation.dst_ip
            proto_match = mitigation.protocol is None or event.protocol.upper() == mitigation.protocol.upper()
            return src_match and dst_match and proto_match
        if mitigation.action == "block_source" and mitigation.src_ip:
            return event.src_ip == mitigation.src_ip
        if mitigation.action == "isolate_port":
            if mitigation.switch_id is None and mitigation.src_ip is None:
                return False
            if mitigation.switch_id and event.switch_id != mitigation.switch_id:
                return False
            if mitigation.src_ip and event.src_ip != mitigation.src_ip:
                return False
            return True
        return False
