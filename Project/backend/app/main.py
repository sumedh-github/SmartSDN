"""FastAPI entrypoint for IDS dashboard backend."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api import router as api_router
from backend.app.mitigation import MitigationService
from backend.app.mode import ModeService
from backend.app.scenario import ScenarioService
from backend.app.store import EventStore


def create_app() -> FastAPI:
    app = FastAPI(title="Intelligent SDN IDS API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.event_store = EventStore()
    app.state.mode_service = ModeService()
    app.state.mitigation_service = MitigationService()
    app.state.scenario_service = ScenarioService(
        store=app.state.event_store,
        mode_service=app.state.mode_service,
    )
    app.include_router(api_router)
    return app


app = create_app()
