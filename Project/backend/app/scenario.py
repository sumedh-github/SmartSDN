"""Scenario event generator for controlled demo runs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from backend.app.mode import ModeService
from backend.app.schemas import FlowEvent, ScenarioDefinition, ScenarioRunRequest
from backend.app.store import EventStore


def _build_event(
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    prediction: str,
    confidence: float,
    packet_count: int,
    byte_count: int,
    scenario: str,
    classification_source: str,
    flow_key: str,
) -> FlowEvent:
    return FlowEvent(
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        prediction=prediction,
        confidence=confidence,
        packet_count=packet_count,
        byte_count=byte_count,
        direction=f"{src_ip}->{dst_ip}",
        flow_key=flow_key,
        switch_id="s1",
        datapath_id="0000000000000001",
        event_source="scenario_runner",
        classification_source=classification_source,
        mode="DEMO_SCENARIO",
        scenario=scenario,
        notes="Generated from demo/scenario mode.",
    )


class ScenarioService:
    """Produces deterministic scenario traffic events for demo reliability."""

    def __init__(self, store: EventStore, mode_service: ModeService) -> None:
        self._store = store
        self._mode_service = mode_service
        self._counter = 0
        self._definitions = [
            ScenarioDefinition(
                code="normal_tcp",
                name="Normal TCP",
                description="Generates benign TCP traffic between Mininet hosts.",
                default_label_source="demo",
            ),
            ScenarioDefinition(
                code="normal_udp",
                name="Normal UDP",
                description="Generates benign UDP traffic between Mininet hosts.",
                default_label_source="demo",
            ),
            ScenarioDefinition(
                code="congestion",
                name="Congestion",
                description="Generates elevated packet rates to represent congestion.",
                default_label_source="hybrid",
            ),
            ScenarioDefinition(
                code="dos_ddos",
                name="DoS/DDoS",
                description="Generates high-volume DoS style traffic sample.",
                default_label_source="demo",
            ),
            ScenarioDefinition(
                code="other_attack",
                name="Other Attack",
                description="Generates rule-driven Other_Attack sample for demonstrations.",
                default_label_source="hybrid",
            ),
        ]
        self._generators: dict[str, Callable[[int], FlowEvent]] = {
            "normal_tcp": self._normal_tcp,
            "normal_udp": self._normal_udp,
            "congestion": self._congestion,
            "dos_ddos": self._dos_ddos,
            "other_attack": self._other_attack,
        }

    def definitions(self) -> list[ScenarioDefinition]:
        return list(self._definitions)

    def clear_demo_state(self) -> int:
        return self._store.clear_demo_events()

    def run(self, request: ScenarioRunRequest) -> int:
        if self._mode_service.get_mode() != "DEMO_SCENARIO":
            raise ValueError("Scenario runner is available only in DEMO_SCENARIO mode.")

        generator = self._generators.get(request.scenario)
        if generator is None:
            raise ValueError(f"Unknown scenario: {request.scenario}")

        for _ in range(request.repeat):
            self._counter += 1
            self._store.add_event(generator(self._counter))
        return request.repeat

    def _normal_tcp(self, counter: int) -> FlowEvent:
        flow_key = f"demo-normal-tcp-{counter}"
        return _build_event(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000 + (counter % 900),
            dst_port=80,
            protocol="TCP",
            prediction="Normal",
            confidence=0.96,
            packet_count=40 + counter,
            byte_count=14000 + (counter * 30),
            scenario="normal_tcp",
            classification_source="demo",
            flow_key=flow_key,
        )

    def _normal_udp(self, counter: int) -> FlowEvent:
        flow_key = f"demo-normal-udp-{counter}"
        return _build_event(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=52000 + (counter % 900),
            dst_port=5353,
            protocol="UDP",
            prediction="Normal",
            confidence=0.94,
            packet_count=28 + counter,
            byte_count=4000 + (counter * 25),
            scenario="normal_udp",
            classification_source="demo",
            flow_key=flow_key,
        )

    def _congestion(self, counter: int) -> FlowEvent:
        flow_key = f"demo-congestion-{counter}"
        return _build_event(
            src_ip="10.0.0.3",
            dst_ip="10.0.0.2",
            src_port=60000 + (counter % 900),
            dst_port=9000,
            protocol="UDP",
            prediction="Congestion",
            confidence=0.88,
            packet_count=260 + (counter * 3),
            byte_count=35000 + (counter * 60),
            scenario="congestion",
            classification_source="hybrid",
            flow_key=flow_key,
        )

    def _dos_ddos(self, counter: int) -> FlowEvent:
        flow_key = f"demo-dos-{counter}"
        return _build_event(
            src_ip="10.0.0.3",
            dst_ip="10.0.0.1",
            src_port=61000 + (counter % 900),
            dst_port=443,
            protocol="TCP",
            prediction="DoS_DDoS",
            confidence=0.95,
            packet_count=500 + (counter * 4),
            byte_count=70000 + (counter * 80),
            scenario="dos_ddos",
            classification_source="demo",
            flow_key=flow_key,
        )

    def _other_attack(self, counter: int) -> FlowEvent:
        flow_key = f"demo-other-attack-{counter}"
        return _build_event(
            src_ip="10.0.0.4",
            dst_ip="10.0.0.2",
            src_port=43000 + (counter % 900),
            dst_port=22,
            protocol="TCP",
            prediction="Other_Attack",
            confidence=0.91,
            packet_count=120 + (counter * 2),
            byte_count=14000 + (counter * 50),
            scenario="other_attack",
            classification_source="hybrid",
            flow_key=flow_key,
        )
