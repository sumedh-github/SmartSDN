# IDS Frontend (React + Vite)

This frontend renders a modern SOC-style SDN security dashboard backed by the FastAPI service.

## Features

- Modern UI login gate (demo/local UI-only access)
- SOC dashboard theme with health/status cards
- Dynamic topology graph from backend/controller data (`/topology`)
- Live controller visibility panel (`/controller/status`)
- Explicit mode indicator and switch:
  - REAL ML MODE
  - DEMO / SCENARIO MODE
- Scenario runner controls (`/scenarios`, `/scenarios/run`, `/scenarios/clear`)
- Raw directional live flow table (`/flows`)
- Grouped session/conversation cards (`/sessions`)
- Mitigation panel:
  - Manual actions (`/mitigate`)
  - Automatic mitigation configuration (`/mitigation/config`)
  - Mitigation event log (`/mitigation/events`)
- Label source visibility on events and sessions:
  - ML
  - Demo
  - Hybrid

## Configuration

Set the backend base URL with:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

If omitted, the app defaults to `http://localhost:8000`.

## Run

```bash
npm install
npm run dev
```

## Notes

- No historical persistence is used; all dashboard state is live and in-memory.
- Demo/scenario controls are available only when DEMO / SCENARIO MODE is active.
- REAL ML MODE uses live controller FT-Transformer labels only.
