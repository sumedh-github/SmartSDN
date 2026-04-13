"""API routes for IDS dashboard data."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.mitigation import MitigationService
from backend.app.schemas import (
    EventIngestResponse,
    FlowEvent,
    HealthResponse,
    MitigationRequest,
    MitigationResponse,
    StatsResponse,
)
from backend.app.store import EventStore

router = APIRouter()


def get_store(request: Request) -> EventStore:
    return request.app.state.event_store


def get_mitigation_service(request: Request) -> MitigationService:
    return request.app.state.mitigation_service


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_event(
    event: FlowEvent,
    store: EventStore = Depends(get_store),
) -> EventIngestResponse:
    store.add_event(event)
    return EventIngestResponse(status="accepted", total_flows=store.total_flows())


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


@router.get("/stats", response_model=StatsResponse)
def stats(store: EventStore = Depends(get_store)) -> StatsResponse:
    return StatsResponse.model_validate(store.stats())


@router.post(
    "/mitigate",
    response_model=MitigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def mitigate(
    request: MitigationRequest,
    service: MitigationService = Depends(get_mitigation_service),
) -> MitigationResponse:
    return MitigationResponse.model_validate(service.register_request(request))
