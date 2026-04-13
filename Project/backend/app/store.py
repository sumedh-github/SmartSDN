"""In-memory store for real-time classified flow events."""

from __future__ import annotations

from collections import Counter
from threading import RLock

from backend.app.schemas import FlowEvent


class EventStore:
    """Thread-safe storage for classified flow events."""

    def __init__(self, max_events: int = 5000) -> None:
        self._lock = RLock()
        self._events: list[FlowEvent] = []
        self._max_events = max_events

    def add_event(self, event: FlowEvent) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events :]

    def total_flows(self) -> int:
        with self._lock:
            return len(self._events)

    def list_flows(self, limit: int = 200) -> list[FlowEvent]:
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def list_alerts(self, limit: int = 200) -> list[FlowEvent]:
        with self._lock:
            alerts = [
                event
                for event in self._events
                if event.prediction.strip().lower() != "normal"
            ]
        return list(reversed(alerts[-limit:]))

    def stats(self) -> dict[str, object]:
        with self._lock:
            events = list(self._events)

        class_distribution = Counter(event.prediction for event in events)
        normal_flows = class_distribution.get("Normal", 0)
        total_flows = len(events)
        suspicious_flows = total_flows - normal_flows
        active_hosts = len({event.src_ip for event in events} | {event.dst_ip for event in events})

        return {
            "total_flows": total_flows,
            "normal_flows": normal_flows,
            "suspicious_flows": suspicious_flows,
            "active_hosts": active_hosts,
            "class_distribution": dict(sorted(class_distribution.items())),
        }
