# IDS Frontend (React + Vite)

React frontend for the SDN SOC dashboard with real backend authentication and protected routes.

## Features

- Login page backed by real backend auth (`POST /auth/login`)
- Token session persistence in `localStorage`
- Protected dashboard routes with redirect to `/login` on invalid session
- Multi-section SOC navigation:
  - Overview Dashboard
  - Topology
  - Raw Flows
  - Sessions
  - Alerts
  - Scenarios
  - Mitigation
  - System / Controller Health
  - Methodology / About
- Dynamic backend-driven topology graph (`GET /topology`)
- Explicit mode indicator:
  - REAL ML MODE
  - DEMO / SCENARIO MODE
- Scenario runner with host-target controls (`POST /scenarios/run`)
- Session-first operations and mitigation controls with rollback
- Source badges and explainability:
  - Label source: ML / Demo / Hybrid
  - Mitigation source: Manual / Automatic

## Configuration

Set backend API base URL:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

Default is `http://localhost:8000`.

## Run

```bash
npm install
npm run dev
```

## Build / lint

```bash
npm run lint
npm run build
```

## Notes

- All runtime dashboard state remains live/in-memory (no DB history).
- Demo/scenario controls are available only in DEMO / SCENARIO MODE.
- REAL ML MODE displays live controller FT-Transformer labels only.
