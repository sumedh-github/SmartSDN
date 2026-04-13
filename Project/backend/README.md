# IDS Backend (FastAPI)

This backend provides dashboard-friendly IDS data through simple REST endpoints.

## Endpoints

- `GET /health`
- `GET /flows`
- `GET /alerts`
- `GET /stats`
- `POST /events`
- `POST /mitigate` (stub, IDS-only mode)

The API starts with an empty in-memory store and is populated only by live controller events.

## Run

From `Project/`:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
