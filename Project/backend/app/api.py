"""API routes for IDS dashboard data."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from backend.app.mitigation import MitigationService
from backend.app.mode import ModeService
from backend.app.scenario import ScenarioService
from backend.app.schemas import (
    AutoMitigationConfig,
    ControllerStatusPayload,
    ControllerStatusResponse,
    EventIngestResponse,
    FlowEvent,
    HealthComponentStatus,
    HealthResponse,
    MitigationConfigUpdateRequest,
    MitigationEvent,
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


@router.get("/health", response_model=HealthResponse)
def health(
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
def get_mode(mode_service: ModeService = Depends(get_mode_service)) -> ModeStatusResponse:
    return ModeStatusResponse.model_validate(mode_service.status())


@router.put("/mode", response_model=ModeStatusResponse)
def update_mode(
    request: ModeUpdateRequest,
    mode_service: ModeService = Depends(get_mode_service),
) -> ModeStatusResponse:
    return ModeStatusResponse.model_validate(mode_service.set_mode(request.mode))


@router.get("/controller/status", response_model=ControllerStatusResponse)
def controller_status(store: EventStore = Depends(get_store)) -> ControllerStatusResponse:
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
) -> EventIngestResponse:
    current_mode = mode_service.get_mode()
    normalized = event.model_copy(update={"mode": current_mode})
    stored_event = store.add_event(normalized)

    if mitigation_service.should_auto_mitigate(stored_event):
        auto_request = mitigation_service.auto_mitigation_request(stored_event)
        mitigation_event = mitigation_service.register_request(auto_request).model_copy(
            update={
                "source_label": stored_event.prediction,
                "source_label_origin": stored_event.classification_source,
            }
        )
        store.register_mitigation(mitigation_event)

    return EventIngestResponse(
        status="accepted",
        total_flows=store.total_flows(),
        mode=current_mode,
    )


@router.get("/flows", response_model=list[FlowEvent])
def flows(
    limit: int = Query(default=200, ge=1, le=5000),
    store: EventStore = Depends(get_store),
) -> list[FlowEvent]:
    return store.list_flows(limit=limit)


@router.get("/alerts", response_model=list[FlowEvent])
def alerts(
    limit: int = Query(default=200, ge=1, le=5000),
    store: EventStore = Depends(get_store),
) -> list[FlowEvent]:
    return store.list_alerts(limit=limit)


@router.get("/sessions", response_model=list[SessionView])
def sessions(
    limit: int = Query(default=500, ge=1, le=5000),
    store: EventStore = Depends(get_store),
) -> list[SessionView]:
    return store.list_sessions(limit=limit)


@router.get("/topology", response_model=TopologyResponse)
def topology(store: EventStore = Depends(get_store)) -> TopologyResponse:
    return store.topology()


@router.get("/stats", response_model=StatsResponse)
def stats(store: EventStore = Depends(get_store)) -> StatsResponse:
    return StatsResponse.model_validate(store.stats())


@router.get("/scenarios", response_model=list[ScenarioDefinition])
def list_scenarios(service: ScenarioService = Depends(get_scenario_service)) -> list[ScenarioDefinition]:
    return service.definitions()


@router.post(
    "/scenarios/run",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def run_scenario(
    request: ScenarioRunRequest,
    service: ScenarioService = Depends(get_scenario_service),
    mode_service: ModeService = Depends(get_mode_service),
) -> ScenarioRunResponse:
    try:
        generated = service.run(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ScenarioRunResponse(
        status="accepted",
        scenario=request.scenario,
        generated_events=generated,
        mode=mode_service.get_mode(),
        message="Scenario events generated in DEMO_SCENARIO mode.",
    )


@router.post(
    "/scenarios/clear",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def clear_scenarios(
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


@router.get("/mitigation/config", response_model=AutoMitigationConfig)
def mitigation_config(
    service: MitigationService = Depends(get_mitigation_service),
) -> AutoMitigationConfig:
    return service.config()


@router.put("/mitigation/config", response_model=AutoMitigationConfig)
def update_mitigation_config(
    request: MitigationConfigUpdateRequest,
    service: MitigationService = Depends(get_mitigation_service),
) -> AutoMitigationConfig:
    return service.update_config(request)


@router.get("/mitigation/events", response_model=list[MitigationEvent])
def mitigation_events(
    limit: int = Query(default=200, ge=1, le=5000),
    store: EventStore = Depends(get_store),
) -> list[MitigationEvent]:
    return store.list_mitigation_events(limit=limit)


@router.post(
    "/mitigate",
    response_model=MitigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def mitigate(
    request: MitigationRequest,
    service: MitigationService = Depends(get_mitigation_service),
    store: EventStore = Depends(get_store),
) -> MitigationResponse:
    mitigation_event = service.register_request(request).model_copy(
        update={
            "source_label": None,
            "source_label_origin": None,
            "timestamp": datetime.now(timezone.utc),
        }
    )
    store.register_mitigation(mitigation_event)
    return MitigationResponse(
        status="accepted",
        mode=service.mode,
        message="Mitigation request recorded. Enforcement is isolated from forwarding logic.",
        event=mitigation_event,
    )
