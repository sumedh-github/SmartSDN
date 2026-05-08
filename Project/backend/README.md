# IDS Backend (FastAPI)

FastAPI backend for the SDN SOC platform with:
- single-admin local auth (`/auth/login`, `/auth/me`, `/auth/logout`)
- explicit REAL ML vs DEMO/SCENARIO mode state
- backend-owned topology/session/alert/flow state
- scenario runner with host targeting + optional helper execution
- manual and automatic mitigation contracts with rollback
- real Mininet/OVS enforcement hooks via `ovs-ofctl`

## Auth endpoints

- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`

All dashboard control/data APIs (except controller ingestion paths) require bearer auth.

## Core monitoring endpoints

- `GET /health`
- `GET /mode`
- `PUT /mode`
- `GET /controller/status`
- `POST /controller/status` (controller ingest)
- `POST /events` (controller ingest)
- `GET /flows`
- `GET /alerts`
- `GET /sessions`
- `GET /topology`
- `GET /stats`

## Scenario endpoints

- `GET /scenarios`
- `POST /scenarios/run`
- `POST /scenarios/reset`
- `POST /scenarios/clear` (compatibility alias)

`POST /scenarios/run` supports host-targeted controls:
- `source_hosts`
- `destination_host`
- `repeat`
- `intensity`
- `packet_size`
- `concurrency`
- `use_real_helpers`

## Mitigation endpoints

- `GET /mitigation/config`
- `PUT /mitigation/config`
- `GET /mitigation/events`
- `POST /mitigations/apply`
- `POST /mitigations/retract`
- `GET /mitigations/active`
- `POST /mitigate` (compatibility alias)

### Mitigation semantics

- `block_flow`: blocks `src_ip + dst_ip + protocol`
- `block_source`: blocks all IPv4 traffic from source host (ARP not blocked)
- `isolate_port`: disables/isolate a switch host-facing port

## Environment variables

### Authentication

- `SOC_ADMIN_USERNAME` (default: `admin`)
- `SOC_ADMIN_EMAIL` (default: `admin@localhost`)
- `SOC_ADMIN_PASSWORD` (default: `admin1234`)
- `SOC_AUTH_SECRET` (default: `change-this-local-secret`)
- `SOC_AUTH_TOKEN_TTL_SEC` (default: `28800`)

### Enforcement

- `SOC_ENFORCEMENT_ENABLED` (default: `true`)
- `SOC_OVS_OFCTL_BIN` (default: `ovs-ofctl`)
- `SOC_OVS_BRIDGE_PREFIX` (default: `s`)

### Scenario helper

- `SOC_SCENARIO_HELPER_CMD` (optional command template for real traffic helper execution)

## Notes

- Storage remains in-memory (live runtime state; no DB).
- No long-term event history is introduced.
- Training/runtime ML feature alignment is unchanged.
- Enforcement and rollback outcomes are explicitly reported; failures are not silently faked.

## Run

From `Project/`:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
