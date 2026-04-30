"""Pydantic schemas for IDS flow events and API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


ModeType = Literal["REAL_ML", "DEMO_SCENARIO"]
LabelSource = Literal["ml", "demo", "hybrid"]
MitigationActionType = Literal["block_flow", "block_source", "isolate_port"]
MitigationTriggerType = Literal["manual", "automatic"]
MitigationStatus = Literal["active", "expired", "retracted", "failed"]
MitigationTargetType = Literal["flow_pair", "source_host", "port"]
EnforcementStatus = Literal["applied", "failed", "not_applied", "retracted"]


class AuthLoginRequest(BaseModel):
    identifier: str
    password: str


class AuthUserResponse(BaseModel):
    username: str
    email: str
    role: str = "admin"


class AuthLoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: AuthUserResponse


class AuthSessionResponse(BaseModel):
    authenticated: bool = True
    user: AuthUserResponse


class FlowEvent(BaseModel):
    event_id: str | None = None
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
    alert_dismissed: bool = False


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
    state: Literal["idle", "normal", "suspicious", "blocked", "disabled"]
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
    source_entity: str
    destination_entity: str
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
    repeat: int = Field(default=1, ge=1, le=200)
    source_hosts: list[str] | None = None
    destination_host: str | None = None
    intensity: int = Field(default=1, ge=1, le=100)
    packet_size: int | None = Field(default=None, ge=64, le=65535)
    concurrency: int = Field(default=1, ge=1, le=64)
    use_real_helpers: bool = False


class ScenarioRunResponse(BaseModel):
    status: str
    scenario: str
    generated_events: int
    mode: ModeType
    message: str
    helper_invoked: bool = False
    helper_requested: bool = False
    helper_output: str | None = None


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
    escalate_after_count: int = Field(default=3, ge=1, le=1000)


class MitigationConfigUpdateRequest(BaseModel):
    enabled: bool | None = None
    suspicious_labels: list[str] | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    default_timeout_sec: int | None = Field(default=None, ge=0, le=86400)
    action_order: list[MitigationActionType] | None = None
    escalate_after_count: int | None = Field(default=None, ge=1, le=1000)


class MitigationRequest(BaseModel):
    action: MitigationActionType = "block_flow"
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    switch_id: str | None = None
    port_id: int | None = Field(default=None, ge=0)
    reason: str | None = None
    timeout_sec: int | None = Field(default=None, ge=0, le=86400)
    triggered_by: MitigationTriggerType = "manual"
    flow_key: str | None = None
    threshold: str | None = None
    condition: str | None = None


class MitigationEvent(BaseModel):
    mitigation_id: str
    timestamp: datetime
    action: MitigationActionType
    target_type: MitigationTargetType
    triggered_by: MitigationTriggerType
    reason: str
    status: MitigationStatus
    enforcement_status: EnforcementStatus = "not_applied"
    enforcement_message: str | None = None
    source_label: str | None = None
    source_label_origin: LabelSource | None = None
    flow_key: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    switch_id: str | None = None
    port_id: int | None = None
    target_summary: str = ""
    threshold: str | None = None
    condition: str | None = None
    expires_at: datetime | None = None
    retracted_at: datetime | None = None


class MitigationResponse(BaseModel):
    status: str
    mode: str
    message: str
    event: MitigationEvent


class MitigationRetractRequest(BaseModel):
    mitigation_id: str
    reason: str | None = None


class MitigationRetractResponse(BaseModel):
    status: str
    message: str
    event: MitigationEvent


class AlertReviewRequest(BaseModel):
    flow_key: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    timestamp: datetime | None = None
    reason: str | None = None


class NormalizeAlertRequest(AlertReviewRequest):
    """Compatibility alias for older normalize-alert endpoint usage."""
    pass


class AlertNormalizeRequest(AlertReviewRequest):
    """Compatibility alias for legacy store import usage."""
    pass


class AlertOverrideRequest(AlertReviewRequest):
    """Compatibility alias for previously named request payload."""
    pass


class AlertOverrideResponse(BaseModel):
    status: str
    message: str
    event: FlowEvent
