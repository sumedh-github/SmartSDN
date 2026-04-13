"""FastAPI entrypoint for IDS dashboard backend."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api import router as api_router
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

    sample_data_path = Path(__file__).resolve().parents[1] / "data" / "sample_events.json"
    app.state.event_store = EventStore(seed_path=sample_data_path)
    app.include_router(api_router)
    return app


app = create_app()
