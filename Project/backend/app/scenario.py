"""Scenario event generator for controlled demo runs."""

from __future__ import annotations

import os
import shlex
import subprocess
from datetime import datetime, timezone
from typing import Callable

from backend.app.enforcement import EnforcementService
from backend.app.mitigation import MitigationService
from backend.app.mode import ModeService
from backend.app.schemas import FlowEvent, ScenarioDefinition, ScenarioRunRequest
from backend.app.store import EventStore

HOST_IP_MAP = {
    "h1": "10.0.0.1",
    "h2": "10.0.0.2",
    "h3": "10.0.0.3",
    "h4": "10.0.0.4",
    "h5": "10.0.0.5",
    "h6": "10.0.0.6",
    "h7": "10.0.0.7",
    "h8": "10.0.0.8",
}


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
    helper_invoked: bool,
) -> FlowEvent:
    helper_notes = "Real helper executed." if helper_invoked else "Generated from demo/scenario mode."
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
        notes=helper_notes,
    )


class ScenarioService:
    """Produces deterministic scenario traffic events for demo reliability."""

    def __init__(
        self,
        store: EventStore,
        mode_service: ModeService,
        mitigation_service: MitigationService,
        enforcement_service: EnforcementService,
    ) -> None:
        self._store = store
        self._mode_service = mode_service
        self._mitigation_service = mitigation_service
        self._enforcement_service = enforcement_service
        self._counter = 0
        self._definitions = [
            ScenarioDefinition(
                code="normal_tcp",
                name="Normal TCP",
                description="Generates benign TCP traffic between selected Mininet hosts.",
                default_label_source="demo",
            ),
            ScenarioDefinition(
                code="normal_udp",
                name="Normal UDP",
                description="Generates benign UDP traffic between selected Mininet hosts.",
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
        self._generators: dict[str, Callable[..., FlowEvent]] = {
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

    def run(self, request: ScenarioRunRequest) -> dict[str, object]:
        if self._mode_service.get_mode() != "DEMO_SCENARIO":
            raise ValueError("Scenario runner is available only in DEMO_SCENARIO mode.")

        generator = self._generators.get(request.scenario)
        if generator is None:
            raise ValueError(f"Unknown scenario: {request.scenario}")

        source_hosts = self._normalize_source_hosts(request.source_hosts)
        destination_host = self._normalize_host(request.destination_host) if request.destination_host else "10.0.0.2"
        helper_requested = bool(request.use_real_helpers)
        helper_invoked = False
        helper_output = None

        if helper_requested:
            helper_invoked, helper_output = self._run_real_helper(request, source_hosts, destination_host)

        generated = 0
        auto_mitigations_applied = 0
        auto_mitigations_failed = 0
        for src_ip in source_hosts:
            for _ in range(request.repeat):
                self._counter += 1
                event = generator(
                    counter=self._counter,
                    src_ip=src_ip,
                    dst_ip=destination_host,
                    intensity=request.intensity,
                    packet_size=request.packet_size,
                    concurrency=request.concurrency,
                    helper_invoked=helper_invoked,
                )
                stored_event = self._store.add_event(event)
                auto_result = self._run_auto_mitigation_if_needed(stored_event)
                if auto_result == "applied":
                    auto_mitigations_applied += 1
                elif auto_result == "failed":
                    auto_mitigations_failed += 1
                generated += 1
        return {
            "scenario": request.scenario,
            "generated_events": generated,
            "helper_requested": helper_requested,
            "helper_invoked": helper_invoked,
            "helper_output": helper_output,
            "auto_mitigations_applied": auto_mitigations_applied,
            "auto_mitigations_failed": auto_mitigations_failed,
        }

    def _run_auto_mitigation_if_needed(self, event: FlowEvent) -> str:
        if not self._mitigation_service.should_auto_mitigate(event):
            return "skipped"

        auto_request = self._mitigation_service.auto_mitigation_request(event)
        mitigation_event = self._mitigation_service.register_request(auto_request).model_copy(
            update={
                "source_label": event.prediction,
                "source_label_origin": event.classification_source,
            }
        )
        enforcement_result = self._enforcement_service.apply(mitigation_event)
        if enforcement_result.ok:
            mitigation_event = mitigation_event.model_copy(
                update={
                    "enforcement_status": "applied",
                    "enforcement_message": enforcement_result.message,
                }
            )
            result = "applied"
        else:
            mitigation_event = mitigation_event.model_copy(
                update={
                    "status": "failed",
                    "enforcement_status": "failed",
                    "enforcement_message": enforcement_result.message,
                }
            )
            result = "failed"
        self._store.register_mitigation(mitigation_event)
        return result

    def _normalize_source_hosts(self, source_hosts: list[str] | None) -> list[str]:
        if not source_hosts:
            return ["10.0.0.1"]
        normalized = [self._normalize_host(value) for value in source_hosts]
        deduped = sorted(set(normalized))
        if not deduped:
            raise ValueError("At least one source host is required.")
        return deduped

    def _normalize_host(self, value: str) -> str:
        raw = value.strip().lower()
        if raw in HOST_IP_MAP:
            return HOST_IP_MAP[raw]
        if raw.startswith("10.0.0."):
            return raw
        raise ValueError(f"Unsupported host selector: {value}")

    def _run_real_helper(
        self,
        request: ScenarioRunRequest,
        source_hosts: list[str],
        destination_host: str,
    ) -> tuple[bool, str | None]:
        helper_cmd = os.getenv("SOC_SCENARIO_HELPER_CMD", "").strip()
        if not helper_cmd:
            return False, "Real helper skipped (SOC_SCENARIO_HELPER_CMD unset); synthetic scenario events still generated."

        command = shlex.split(helper_cmd)
        command.extend(
            [
                "--scenario",
                request.scenario,
                "--sources",
                ",".join(source_hosts),
                "--destination",
                destination_host,
                "--repeat",
                str(request.repeat),
                "--intensity",
                str(request.intensity),
                "--concurrency",
                str(request.concurrency),
            ]
        )
        if request.packet_size is not None:
            command.extend(["--packet-size", str(request.packet_size)])
        proc = subprocess.run(command, check=False, capture_output=True, text=True)
        output = (proc.stdout or proc.stderr or "").strip()[:500]
        if proc.returncode != 0:
            return False, f"Helper failed (code {proc.returncode}): {output}"
        return True, output or "Helper executed."

    def _normal_tcp(
        self,
        *,
        counter: int,
        src_ip: str,
        dst_ip: str,
        intensity: int,
        packet_size: int | None,
        concurrency: int,
        helper_invoked: bool,
    ) -> FlowEvent:
        flow_key = f"demo-normal-tcp-{counter}"
        bytes_base = packet_size or 1400
        return _build_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=45000 + (counter % 900),
            dst_port=80,
            protocol="TCP",
            prediction="Normal",
            confidence=0.96,
            packet_count=40 + (intensity * 2) + counter,
            byte_count=(bytes_base * max(8, intensity)) + (counter * 30),
            scenario="normal_tcp",
            classification_source="demo",
            flow_key=flow_key,
            helper_invoked=helper_invoked,
        )

    def _normal_udp(
        self,
        *,
        counter: int,
        src_ip: str,
        dst_ip: str,
        intensity: int,
        packet_size: int | None,
        concurrency: int,
        helper_invoked: bool,
    ) -> FlowEvent:
        flow_key = f"demo-normal-udp-{counter}"
        bytes_base = packet_size or 1200
        return _build_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=52000 + (counter % 900),
            dst_port=5353,
            protocol="UDP",
            prediction="Normal",
            confidence=0.94,
            packet_count=28 + intensity + counter,
            byte_count=(bytes_base * max(4, intensity)) + (counter * 25),
            scenario="normal_udp",
            classification_source="demo",
            flow_key=flow_key,
            helper_invoked=helper_invoked,
        )

    def _congestion(
        self,
        *,
        counter: int,
        src_ip: str,
        dst_ip: str,
        intensity: int,
        packet_size: int | None,
        concurrency: int,
        helper_invoked: bool,
    ) -> FlowEvent:
        flow_key = f"demo-congestion-{counter}"
        bytes_base = packet_size or 1400
        return _build_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=60000 + (counter % 900),
            dst_port=9000,
            protocol="UDP",
            prediction="Congestion",
            confidence=0.88,
            packet_count=250 + (intensity * 12) + (concurrency * 8) + (counter * 3),
            byte_count=(bytes_base * max(30, intensity * concurrency)) + (counter * 60),
            scenario="congestion",
            classification_source="hybrid",
            flow_key=flow_key,
            helper_invoked=helper_invoked,
        )

    def _dos_ddos(
        self,
        *,
        counter: int,
        src_ip: str,
        dst_ip: str,
        intensity: int,
        packet_size: int | None,
        concurrency: int,
        helper_invoked: bool,
    ) -> FlowEvent:
        flow_key = f"demo-dos-{counter}"
        bytes_base = packet_size or 1500
        return _build_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=61000 + (counter % 900),
            dst_port=443,
            protocol="TCP",
            prediction="DoS_DDoS",
            confidence=0.95,
            packet_count=420 + (intensity * 22) + (concurrency * 20) + (counter * 4),
            byte_count=(bytes_base * max(45, intensity * concurrency)) + (counter * 80),
            scenario="dos_ddos",
            classification_source="demo",
            flow_key=flow_key,
            helper_invoked=helper_invoked,
        )

    def _other_attack(
        self,
        *,
        counter: int,
        src_ip: str,
        dst_ip: str,
        intensity: int,
        packet_size: int | None,
        concurrency: int,
        helper_invoked: bool,
    ) -> FlowEvent:
        flow_key = f"demo-other-attack-{counter}"
        bytes_base = packet_size or 1300
        return _build_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=43000 + (counter % 900),
            dst_port=22,
            protocol="TCP",
            prediction="Other_Attack",
            confidence=0.91,
            packet_count=120 + (intensity * 8) + (concurrency * 3) + (counter * 2),
            byte_count=(bytes_base * max(10, intensity * concurrency)) + (counter * 50),
            scenario="other_attack",
            classification_source="hybrid",
            flow_key=flow_key,
            helper_invoked=helper_invoked,
        )
