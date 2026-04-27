# IDS Backend (FastAPI)

The backend provides live, in-memory APIs for:
- real controller ML flow events
- dynamic topology model
- grouped sessions/conversations
- explicit mode management (REAL_ML vs DEMO_SCENARIO)
- scenario runner controls
- manual + configurable automatic mitigation logging

## Core endpoints

- `GET /health`
- `GET /mode`
- `PUT /mode`
- `GET /controller/status`
- `POST /controller/status`
- `POST /events`
- `GET /flows`
- `GET /alerts`
- `GET /sessions`
- `GET /topology`
- `GET /stats`

## Scenario endpoints

- `GET /scenarios`
- `POST /scenarios/run`
- `POST /scenarios/clear`

## Mitigation endpoints

- `GET /mitigation/config`
- `PUT /mitigation/config`
- `GET /mitigation/events`
- `POST /mitigate`

## Notes

- Storage is intentionally in-memory (live events only).
- No historical persistence is added.
- Mitigation actions are logged and reflected in UI state, while forwarding logic remains isolated in the controller path.

## Run

From `Project/`:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
