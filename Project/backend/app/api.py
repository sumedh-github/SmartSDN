"""API routes for IDS dashboard data."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from backend.app.schemas import FlowEvent, HealthResponse, StatsResponse
from backend.app.store import EventStore

router = APIRouter()


def get_store(request: Request) -> EventStore:
    return request.app.state.event_store


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


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
