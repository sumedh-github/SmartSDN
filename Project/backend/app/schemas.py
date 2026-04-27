"""Pydantic schemas for IDS flow events and API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


ModeType = Literal["REAL_ML", "DEMO_SCENARIO"]
LabelSource = Literal["ml", "demo", "hybrid"]
MitigationActionType = Literal["block_flow", "block_source", "isolate_port"]
MitigationTriggerType = Literal["manual", "automatic"]


class FlowEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0)
    dst_port: int = Field(ge=0)
    protocol: str
    prediction: str
    confidence: float = Field(ge=0.0, le=1.0)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    direction: str | None = None
    flow_key: str | None = None
    switch_id: str | None = None
    datapath_id: str | None = None
    event_source: str = "controller"
    classification_source: LabelSource = "ml"
    mode: ModeType = "REAL_ML"
    scenario: str | None = None
    notes: str | None = None
    mitigation_state: str = "none"


class HealthComponentStatus(BaseModel):
    backend: str
    controller: str
    topology: str
    live_event_stream: str
    mode: ModeType
    mitigation_automatic_enabled: bool


class HealthResponse(BaseModel):
    status: str
    components: HealthComponentStatus | None = None


class StatsResponse(BaseModel):
    total_flows: int
    normal_flows: int
    suspicious_flows: int
    active_hosts: int
    class_distribution: dict[str, int]
    by_source: dict[str, int] = Field(default_factory=dict)
    mitigated_flows: int = 0


class EventIngestResponse(BaseModel):
    status: str
    total_flows: int
    mode: ModeType


class TopologyNode(BaseModel):
    id: str
    kind: Literal["controller", "switch", "host"]
    label: str
    status: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyLink(BaseModel):
    id: str
    source: str
    target: str
    state: Literal["idle", "normal", "suspicious", "blocked"]
    flow_count: int = 0
    packet_count: int = 0
    byte_count: int = 0


class TopologyTrafficEdge(BaseModel):
    id: str
    source: str
    target: str
    state: Literal["normal", "suspicious", "blocked"]
    dominant_label: str
    confidence: float = Field(ge=0.0, le=1.0)
    classification_source: LabelSource
    flow_count: int = 0


class TopologyResponse(BaseModel):
    generated_at: datetime
    nodes: list[TopologyNode]
    links: list[TopologyLink]
    traffic_edges: list[TopologyTrafficEdge]


class SessionView(BaseModel):
    session_id: str
    protocol: str
    endpoints: list[str]
    participants: list[str]
    flow_count: int
    dominant_label: str
    dominant_label_source: LabelSource
    confidence_avg: float = Field(ge=0.0, le=1.0)
    confidence_max: float = Field(ge=0.0, le=1.0)
    suspicious: bool
    mitigation_state: str
    latest_seen: datetime
    total_packets: int
    total_bytes: int


class ModeStatusResponse(BaseModel):
    mode: ModeType
    description: str


class ModeUpdateRequest(BaseModel):
    mode: ModeType


class ScenarioDefinition(BaseModel):
    code: str
    name: str
    description: str
    default_label_source: LabelSource


class ScenarioRunRequest(BaseModel):
    scenario: str
    repeat: int = Field(default=1, ge=1, le=50)


class ScenarioRunResponse(BaseModel):
    status: str
    scenario: str
    generated_events: int
    mode: ModeType
    message: str


class ControllerStatusPayload(BaseModel):
    timestamp: datetime
    running: bool = True
    polling_active: bool = True
    model_loaded: bool = True
    mode: ModeType = "REAL_ML"
    datapath_count: int = Field(default=0, ge=0)
    backend_events_url: str | None = None


class ControllerStatusResponse(ControllerStatusPayload):
    stale: bool = False


class AutoMitigationConfig(BaseModel):
    enabled: bool = False
    suspicious_labels: list[str] = Field(
        default_factory=lambda: ["DoS_DDoS", "Other_Attack", "Congestion"]
    )
    min_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    default_timeout_sec: int = Field(default=300, ge=0, le=86400)
    action_order: list[MitigationActionType] = Field(
        default_factory=lambda: ["block_flow", "block_source", "isolate_port"]
    )


class MitigationConfigUpdateRequest(BaseModel):
    enabled: bool | None = None
    suspicious_labels: list[str] | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    default_timeout_sec: int | None = Field(default=None, ge=0, le=86400)
    action_order: list[MitigationActionType] | None = None


class MitigationRequest(BaseModel):
    flow_key: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    switch_id: str | None = None
    port_id: int | None = Field(default=None, ge=0)
    action: MitigationActionType = "block_flow"
    reason: str | None = None
    timeout_sec: int | None = Field(default=None, ge=0, le=86400)
    triggered_by: MitigationTriggerType = "manual"


class MitigationEvent(BaseModel):
    mitigation_id: str
    timestamp: datetime
    action: MitigationActionType
    triggered_by: MitigationTriggerType
    reason: str
    status: str
    source_label: str | None = None
    source_label_origin: LabelSource | None = None
    flow_key: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    switch_id: str | None = None
    port_id: int | None = None
    expires_at: datetime | None = None


class MitigationResponse(BaseModel):
    status: str
    mode: str
    message: str
    event: MitigationEvent
