"""API routes for IDS dashboard data."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from backend.app.auth import AuthService
from backend.app.enforcement import EnforcementService
from backend.app.mitigation import MitigationService
from backend.app.mode import ModeService
from backend.app.scenario import ScenarioService
from backend.app.schemas import (
    AlertReviewRequest,
    AutoMitigationConfig,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthSessionResponse,
    AuthUserResponse,
    ControllerStatusPayload,
    ControllerStatusResponse,
    EventIngestResponse,
    FlowEvent,
    HealthComponentStatus,
    HealthResponse,
    MitigationConfigUpdateRequest,
    MitigationEvent,
    MitigationRetractRequest,
    MitigationRetractResponse,
    MitigationRequest,
    MitigationResponse,
    ModeStatusResponse,
    ModeUpdateRequest,
    ScenarioDefinition,
    ScenarioRunRequest,
    ScenarioRunResponse,
    SessionView,
    StatsResponse,
    TopologyResponse,
)
from backend.app.store import EventStore

router = APIRouter()


def get_store(request: Request) -> EventStore:
    return request.app.state.event_store


def get_mitigation_service(request: Request) -> MitigationService:
    return request.app.state.mitigation_service


def get_mode_service(request: Request) -> ModeService:
    return request.app.state.mode_service


def get_scenario_service(request: Request) -> ScenarioService:
    return request.app.state.scenario_service


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_enforcement_service(request: Request) -> EnforcementService:
    return request.app.state.enforcement_service


def _resolve_flow_protocol(flow_event: FlowEvent) -> str | None:
    protocol = flow_event.protocol.strip().upper() if flow_event.protocol else ""
    if protocol in {"TCP", "UDP"}:
        return protocol
    if flow_event.flow_key:
        parts = flow_event.flow_key.split("|")
        if len(parts) >= 3:
            proto_code = parts[2]
            if proto_code == "6":
                return "TCP"
            if proto_code == "17":
                return "UDP"
    return None


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token.",
        )
    parts = authorization.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed bearer token.",
        )
    return parts[1].strip()


def require_authenticated_user(
    authorization: str | None = Header(default=None),
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthUserResponse:
    token = _extract_bearer_token(authorization)
    try:
        user = auth_service.validate_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return AuthUserResponse(username=user.username, email=user.email, role=user.role)


def _apply_mitigation_request(
    *,
    request: MitigationRequest,
    service: MitigationService,
    store: EventStore,
    enforcement: EnforcementService,
    source_label: str | None,
    source_label_origin: str | None,
) -> MitigationEvent:
    normalized_request = request
    if request.action == "block_flow" and request.protocol is None and request.flow_key:
        flow_records = store.list_flows(limit=5000)
        match = next((record for record in flow_records if record.flow_key == request.flow_key), None)
        if match is not None:
            normalized_request = request.model_copy(
                update={
                    "src_ip": request.src_ip or match.src_ip,
                    "dst_ip": request.dst_ip or match.dst_ip,
                    "protocol": _resolve_flow_protocol(match),
                }
            )

    mitigation_event = service.register_request(normalized_request).model_copy(
        update={
            "source_label": source_label,
            "source_label_origin": source_label_origin,
            "timestamp": datetime.now(timezone.utc),
        }
    )
    result = enforcement.apply(mitigation_event)
    if result.ok:
        mitigation_event = mitigation_event.model_copy(
            update={
                "enforcement_status": "applied",
                "enforcement_message": result.message,
            }
        )
    else:
        mitigation_event = mitigation_event.model_copy(
            update={
                "status": "failed",
                "enforcement_status": "failed",
                "enforcement_message": result.message,
            }
        )
    store.register_mitigation(mitigation_event)
    return mitigation_event


@router.post("/auth/login", response_model=AuthLoginResponse)
def login(
    request: AuthLoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthLoginResponse:
    try:
        token, user, expires_at = auth_service.login(
            identifier=request.identifier,
            password=request.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return AuthLoginResponse(
        token=token,
        expires_at=expires_at,
        user=AuthUserResponse(username=user.username, email=user.email, role=user.role),
    )


@router.get("/auth/me", response_model=AuthSessionResponse)
def auth_me(user: AuthUserResponse = Depends(require_authenticated_user)) -> AuthSessionResponse:
    return AuthSessionResponse(authenticated=True, user=user)


@router.post("/auth/logout")
def auth_logout(_: AuthUserResponse = Depends(require_authenticated_user)) -> dict[str, str]:
    # Stateless token model: logout is handled by clearing token on client.
    return {"status": "ok", "message": "Session closed on client side."}


@router.get("/health", response_model=HealthResponse)
def health(
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
    mode_service: ModeService = Depends(get_mode_service),
    mitigation_service: MitigationService = Depends(get_mitigation_service),
) -> HealthResponse:
    components = store.system_health(
        mode=mode_service.get_mode(),
        mitigation_automatic_enabled=mitigation_service.config().enabled,
    )
    return HealthResponse(
        status="ok",
        components=HealthComponentStatus.model_validate(components),
    )


@router.get("/mode", response_model=ModeStatusResponse)
def get_mode(
    _: AuthUserResponse = Depends(require_authenticated_user),
    mode_service: ModeService = Depends(get_mode_service),
) -> ModeStatusResponse:
    return ModeStatusResponse.model_validate(mode_service.status())


@router.put("/mode", response_model=ModeStatusResponse)
def update_mode(
    request: ModeUpdateRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    mode_service: ModeService = Depends(get_mode_service),
) -> ModeStatusResponse:
    return ModeStatusResponse.model_validate(mode_service.set_mode(request.mode))


@router.get("/controller/status", response_model=ControllerStatusResponse)
def controller_status(
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> ControllerStatusResponse:
    return store.controller_status()


@router.post(
    "/controller/status",
    response_model=ControllerStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def controller_status_ingest(
    payload: ControllerStatusPayload,
    store: EventStore = Depends(get_store),
) -> ControllerStatusResponse:
    store.upsert_controller_status(payload)
    return store.controller_status()


@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_event(
    event: FlowEvent,
    store: EventStore = Depends(get_store),
    mode_service: ModeService = Depends(get_mode_service),
    mitigation_service: MitigationService = Depends(get_mitigation_service),
    enforcement_service: EnforcementService = Depends(get_enforcement_service),
) -> EventIngestResponse:
    current_mode = mode_service.get_mode()
    normalized = event.model_copy(update={"mode": current_mode})
    stored_event = store.add_event(normalized)

    if mitigation_service.should_auto_mitigate(stored_event):
        auto_request = mitigation_service.auto_mitigation_request(stored_event)
        _apply_mitigation_request(
            request=auto_request,
            service=mitigation_service,
            store=store,
            enforcement=enforcement_service,
            source_label=stored_event.prediction,
            source_label_origin=stored_event.classification_source,
        )

    return EventIngestResponse(
        status="accepted",
        total_flows=store.total_flows(),
        mode=current_mode,
    )


@router.get("/flows", response_model=list[FlowEvent])
def flows(
    limit: int = Query(default=200, ge=1, le=5000),
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> list[FlowEvent]:
    return store.list_flows(limit=limit)


@router.get("/alerts", response_model=list[FlowEvent])
def alerts(
    limit: int = Query(default=200, ge=1, le=5000),
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> list[FlowEvent]:
    return store.list_alerts(limit=limit)


@router.post("/alerts/mark-normal", response_model=FlowEvent)
def mark_alert_normal(
    request: AlertReviewRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> FlowEvent:
    try:
        return store.mark_alert_as_normal(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/alerts/mark-mitigated", response_model=FlowEvent)
def mark_alert_mitigated(
    request: AlertReviewRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> FlowEvent:
    try:
        return store.dismiss_alert(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/sessions", response_model=list[SessionView])
def sessions(
    limit: int = Query(default=500, ge=1, le=5000),
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> list[SessionView]:
    return store.list_sessions(limit=limit)


@router.get("/topology", response_model=TopologyResponse)
def topology(
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> TopologyResponse:
    return store.topology()


@router.get("/stats", response_model=StatsResponse)
def stats(
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> StatsResponse:
    return StatsResponse.model_validate(store.stats())


@router.get("/scenarios", response_model=list[ScenarioDefinition])
def list_scenarios(
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: ScenarioService = Depends(get_scenario_service),
) -> list[ScenarioDefinition]:
    return service.definitions()


@router.post(
    "/scenarios/run",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def run_scenario(
    request: ScenarioRunRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: ScenarioService = Depends(get_scenario_service),
    mode_service: ModeService = Depends(get_mode_service),
) -> ScenarioRunResponse:
    try:
        result = service.run(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ScenarioRunResponse(
        status="accepted",
        scenario=request.scenario,
        generated_events=int(result["generated_events"]),
        mode=mode_service.get_mode(),
        message="Scenario events generated in DEMO_SCENARIO mode.",
        helper_invoked=bool(result["helper_invoked"]),
        helper_requested=bool(result["helper_requested"]),
        helper_output=result["helper_output"],
    )


@router.post(
    "/scenarios/clear",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def clear_scenarios(
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: ScenarioService = Depends(get_scenario_service),
    mode_service: ModeService = Depends(get_mode_service),
) -> ScenarioRunResponse:
    removed = service.clear_demo_state()
    return ScenarioRunResponse(
        status="accepted",
        scenario="clear",
        generated_events=removed,
        mode=mode_service.get_mode(),
        message="Demo/scenario events removed from live memory store.",
    )


@router.post(
    "/scenarios/reset",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def reset_scenarios(
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: ScenarioService = Depends(get_scenario_service),
    mode_service: ModeService = Depends(get_mode_service),
) -> ScenarioRunResponse:
    removed = service.clear_demo_state()
    return ScenarioRunResponse(
        status="accepted",
        scenario="reset",
        generated_events=removed,
        mode=mode_service.get_mode(),
        message="Demo/scenario events reset from live memory store.",
    )


@router.get("/mitigation/config", response_model=AutoMitigationConfig)
def mitigation_config(
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: MitigationService = Depends(get_mitigation_service),
) -> AutoMitigationConfig:
    return service.config()


@router.put("/mitigation/config", response_model=AutoMitigationConfig)
def update_mitigation_config(
    request: MitigationConfigUpdateRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: MitigationService = Depends(get_mitigation_service),
) -> AutoMitigationConfig:
    return service.update_config(request)


@router.get("/mitigation/events", response_model=list[MitigationEvent])
def mitigation_events(
    limit: int = Query(default=200, ge=1, le=5000),
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> list[MitigationEvent]:
    return store.list_mitigation_events(limit=limit)


@router.post(
    "/mitigations/apply",
    response_model=MitigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def apply_mitigation(
    request: MitigationRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: MitigationService = Depends(get_mitigation_service),
    store: EventStore = Depends(get_store),
    enforcement_service: EnforcementService = Depends(get_enforcement_service),
) -> MitigationResponse:
    try:
        mitigation_event = _apply_mitigation_request(
            request=request,
            service=service,
            store=store,
            enforcement=enforcement_service,
            source_label=None,
            source_label_origin=None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    accepted = mitigation_event.status == "active"
    message = (
        "Mitigation applied and enforced in Mininet/OVS."
        if accepted
        else "Mitigation request recorded but enforcement failed."
    )
    return MitigationResponse(
        status="accepted" if accepted else "failed",
        mode=service.mode,
        message=message,
        event=mitigation_event,
    )


@router.post(
    "/mitigate",
    response_model=MitigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def mitigate_legacy(
    request: MitigationRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    service: MitigationService = Depends(get_mitigation_service),
    store: EventStore = Depends(get_store),
    enforcement_service: EnforcementService = Depends(get_enforcement_service),
) -> MitigationResponse:
    try:
        mitigation_event = _apply_mitigation_request(
            request=request,
            service=service,
            store=store,
            enforcement=enforcement_service,
            source_label=None,
            source_label_origin=None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    accepted = mitigation_event.status == "active"
    return MitigationResponse(
        status="accepted" if accepted else "failed",
        mode=service.mode,
        message=(
            "Mitigation applied and enforced in Mininet/OVS."
            if accepted
            else "Mitigation request recorded but enforcement failed."
        ),
        event=mitigation_event,
    )


@router.get("/mitigations/active", response_model=list[MitigationEvent])
def active_mitigations(
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
) -> list[MitigationEvent]:
    return store.list_active_mitigations()


@router.post("/mitigations/retract", response_model=MitigationRetractResponse)
def retract_mitigation(
    request: MitigationRetractRequest,
    _: AuthUserResponse = Depends(require_authenticated_user),
    store: EventStore = Depends(get_store),
    enforcement_service: EnforcementService = Depends(get_enforcement_service),
) -> MitigationRetractResponse:
    mitigation_event = store.get_mitigation(request.mitigation_id)
    if mitigation_event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mitigation ID not found.")

    if mitigation_event.status != "active":
        return MitigationRetractResponse(
            status="ignored",
            message=f"Mitigation already {mitigation_event.status}.",
            event=mitigation_event,
        )

    result = enforcement_service.retract(mitigation_event)
    if result.ok:
        updated = mitigation_event.model_copy(
            update={
                "status": "retracted",
                "enforcement_status": "retracted",
                "enforcement_message": result.message,
                "retracted_at": datetime.now(timezone.utc),
                "reason": request.reason or mitigation_event.reason,
            }
        )
        store.update_mitigation(updated)
        return MitigationRetractResponse(
            status="accepted",
            message="Mitigation rollback applied.",
            event=updated,
        )

    updated = mitigation_event.model_copy(
        update={
            "enforcement_status": "failed",
            "enforcement_message": result.message,
        }
    )
    store.update_mitigation(updated)
    return MitigationRetractResponse(
        status="failed",
        message="Mitigation rollback failed.",
        event=updated,
    )
