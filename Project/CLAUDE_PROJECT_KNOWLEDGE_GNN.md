# AI-SDN / smartSDN Project Knowledge File (for Claude)

Use this document as the **single context handoff** when asking Claude to draft your final project report.

## 1) Project identity and objective

- **Project type:** Intelligent SDN security operations platform (research/demo SOC style)
- **Core goal:** Detect suspicious traffic in an SDN lab using a GNN model, visualize the network state in near real-time, and apply operator-driven or automatic mitigations through OpenFlow/OVS.
- **Deployment style:** Local lab stack (Mininet + Open vSwitch + Ryu + FastAPI + React), designed for demos and academic evaluation.

## 2) High-level architecture

```text
Mininet hosts/switches
        |
        v
Ryu controller (OpenFlow 1.3) + GNN inference
        |
        | POST /events, POST /controller/status
        v
FastAPI backend (in-memory event + mitigation store, auth, APIs)
        |
        v
React dashboard (auth-protected monitoring + control UI)
```

## 3) Repository structure (important paths)

```text
Project/
├── Controller/
│   └── ids_switch.py                  # Ryu learning switch + ML inference + backend emit
├── backend/
│   └── app/
│       ├── main.py                    # FastAPI app wiring + services
│       ├── api.py                     # REST endpoints
│       ├── auth.py                    # local single-admin token auth
│       ├── mode.py                    # REAL_ML vs DEMO_SCENARIO runtime mode
│       ├── mitigation.py              # mitigation config + auto-trigger logic
│       ├── enforcement.py             # ovs-ofctl apply/retract enforcement
│       ├── scenario.py                # synthetic scenario generator + optional helper
│       ├── store.py                   # in-memory event/topology/session/mitigation state
│       └── schemas.py                 # Pydantic contracts
├── frontend/
│   ├── src/App.jsx                    # main authenticated dashboard app
│   ├── src/LoginGate.jsx              # login form
│   └── src/App.css                    # dashboard styling
├── ml/
│   ├── config.py                      # feature schema + class mapping
│   ├── preprocess.py
│   ├── train_transformer.py
│   ├── evaluate.py
│   └── artifacts/                     # model/scaler/encoder/schema
└── requirements.txt
```

## 4) Technology stack

- **Network emulation:** Mininet, Open vSwitch (OVS), OpenFlow 1.3
- **Controller:** Ryu (Python, eventlet)
- **ML:** PyTorch GNN + sklearn/joblib preprocessing artifacts
- **Backend API:** FastAPI + Pydantic
- **Frontend:** React + Vite + react-router-dom
- **State model:** In-memory backend store (non-persistent by design)

## 5) Runtime modes and source-of-truth semantics

### REAL_ML
- Uses live controller inference events.
- `classification_source` is `ml`.
- Intended for actual model-driven detection from observed traffic.

### DEMO_SCENARIO
- Allows synthetic scenario generation for reliable demos.
- Events are explicitly marked with `event_source="scenario_runner"` and `classification_source="demo"` or `"hybrid"`.
- Auto mitigation can still run against scenario-generated events.

## 6) End-to-end data flow

1. Mininet traffic reaches OVS switches.
2. Ryu polls flow stats and builds feature vectors.
3. GNN predicts label/confidence.
4. Controller emits structured events to backend (`POST /events`).
5. Backend stores events, updates sessions/topology/stats, and may trigger automatic mitigation.
6. Frontend polls API endpoints and renders dashboard sections.
7. Manual actions from frontend call mitigation endpoints; backend executes OVS enforcement and records mitigation lifecycle.

## 7) Key backend API contracts (auth required except ingest endpoints)

### Authentication
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`

### Monitoring and telemetry
- `GET /health`
- `GET /mode`
- `PUT /mode`
- `GET /controller/status`
- `POST /controller/status` (controller -> backend)
- `POST /events` (controller -> backend)
- `GET /flows`
- `GET /alerts`
- `GET /sessions`
- `GET /topology`
- `GET /stats`

### Alert workflow
- `POST /alerts/mark-normal`
- `POST /alerts/mark-mitigated`

### Scenario runner
- `GET /scenarios`
- `POST /scenarios/run`
- `POST /scenarios/clear`
- `POST /scenarios/reset`

### Mitigation
- `GET /mitigation/config`
- `PUT /mitigation/config`
- `GET /mitigation/events`
- `GET /mitigations/active`
- `POST /mitigations/apply`
- `POST /mitigations/retract`
- `POST /mitigate` (legacy compatibility alias)

## 8) Authentication model

- Single local admin account from environment variables.
- Stateless signed bearer token (JWT-like, HS256 HMAC).
- Frontend stores session in `localStorage` (`soc.auth.session`).
- Protected routes redirect to `/login` when unauthenticated.

Environment keys:
- `SOC_ADMIN_USERNAME` (default `admin`)
- `SOC_ADMIN_EMAIL` (default `admin@localhost`)
- `SOC_ADMIN_PASSWORD` (default `admin1234`)
- `SOC_AUTH_SECRET` (default placeholder secret)
- `SOC_AUTH_TOKEN_TTL_SEC` (default `28800`)

## 9) Mitigation model (manual + automatic)

Supported actions:
1. `block_flow` (flow pair)
2. `block_source` (source host IPv4-wide)
3. `isolate_port` (interpreted as switch isolation when `port_id=0`)

Important implemented semantics:
- **Block Flow Pair** accepts protocol `TCP`, `UDP`, `ICMP`, or `ALL`.
- For `ALL`, enforcement uses `ip` match to block IPv4 across protocols.
- **Block Source Host** blocks IPv4 from source host across discovered bridges.
- **Isolate Port** with `port_id=0` enumerates switch data ports via `ovs-ofctl dump-ports-desc` and brings them down (`mod-port ... down`).
- Enforcement tracks applied bridge/cookie or bridge/port mappings to support rollback.
- Rollback restores flow rules or re-enables ports.

Automatic mitigation behavior:
- Disabled by default.
- Trigger requires:
  - enabled config
  - label in suspicious labels
  - confidence >= threshold
  - escalation count reached (`escalate_after_count`)
- Uses cooldown map to prevent repeated duplicate triggers within active timeout window.
- Primary auto action is derived from `action_order[0]`.

## 10) Topology/session/alert behavior

### Sessions
- Grouped as conversations by `(protocol, sorted endpoint pair)`.
- Shows dominant label/source, confidence aggregates, packet/byte totals, latest timestamp, mitigation state.

### Alerts
- Derived from suspicious labels and filtered for `alert_dismissed == False`.
- "Mark as normal" converts event label to `Normal` with audit note.
- "Flow mitigated" dismisses alert from active alert list.

### Topology
- Derived from in-memory events and active mitigations.
- Includes controller node, switch nodes, host nodes, host links, and traffic edges.
- Link states include `idle`, `normal`, `suspicious`, `blocked`, `disabled`.
- Host/switch/link status reflects mitigation impact where applicable.

## 11) Scenario engine details

Built-in scenarios:
- `normal_tcp`
- `normal_udp`
- `congestion`
- `dos_ddos`
- `other_attack`

Request controls include:
- `repeat`
- `source_hosts`
- `destination_host`
- `intensity`
- `packet_size`
- `concurrency`
- `use_real_helpers`

Optional external helper:
- `SOC_SCENARIO_HELPER_CMD`
- If unset and helper requested, API reports helper not invoked and still generates synthetic events.

## 12) Controller behavior (Ryu + ML)

Controller file: `Controller/ids_switch.py`

Highlights:
- OpenFlow 1.3 learning switch baseline.
- Polls flow stats every 2 seconds.
- Feature extraction aligned with `ml/config.py` `FEATURE_COLUMNS`.
- Loads scaler/encoder/model artifacts from `ml/artifacts`.
- Classifies eligible IPv4 TCP/UDP flows, emits confidence-scored events.
- Sends controller heartbeat/status payload to backend.

Controller backend env keys:
- `IDS_BACKEND_EVENTS_URL`
- `IDS_BACKEND_CONTROLLER_STATUS_URL`
- `IDS_BACKEND_EMIT_TIMEOUT_SEC`

## 13) Enforcement and OVS integration details

Enforcement file: `backend/app/enforcement.py`

Key implementation notes:
- Uses `ovs-ofctl` with explicit `-O OpenFlow13` to avoid protocol mismatch.
- Optional sudo fallback (`sudo -n`) for socket permission errors.
- Can probe multiple bridges (`s1..sN`) for broad flow/source blocks.
- Handles missing bridges/ports gracefully when searching candidates.
- Maintains internal tables to retract exactly what was applied.

Relevant env keys:
- `SOC_ENFORCEMENT_ENABLED`
- `SOC_OVS_BRIDGE_PREFIX`
- `SOC_SOURCE_BLOCK_BRIDGE_MAX`
- `SOC_OVS_OFCTL_BIN`
- `SOC_OVS_OPENFLOW_VERSION`
- `SOC_OVS_USE_SUDO`

## 14) Frontend UX behavior (current branch)

Main UI traits:
- Protected dashboard with navigation sections:
  - Overview
  - Topology ("Network Map")
  - Raw Flows
  - Sessions (grouped primary view)
  - Alerts
  - Scenarios
  - Mitigation
  - System/Controller Health
- Mode banner differentiates REAL_ML vs DEMO_SCENARIO.
- Label-source pills (ML / Demo / Hybrid).
- Manual mitigation forms + auto-mitigation config editing.
- Alert action buttons for false-positive normalization and mitigation dismissal.
- Robust polling using parallel requests and partial-failure tolerance.

## 15) Operational setup quick commands

```bash
# Backend
cd Project
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# Controller
cd Project
ryu-manager Controller/ids_switch.py

# Frontend
cd Project/frontend
npm run dev

# Mininet (example)
sudo mn --topo single,3 --mac --switch ovsk,protocols=OpenFlow13 --controller remote
```

## 16) Common troubleshooting knowledge

1. **OVS permission denied**
   - Enable sudo fallback (`SOC_OVS_USE_SUDO=true`) and configure passwordless `ovs-ofctl` in sudoers if needed.

2. **OpenFlow version negotiation / broken pipe**
   - Ensure `ovs-ofctl` commands use OpenFlow 1.3 (`-O OpenFlow13`).

3. **Scenario helper warning**
   - If `SOC_SCENARIO_HELPER_CMD` is unset, synthetic events are still generated. This is expected behavior.

4. **Import errors for alert request schemas**
   - Compatibility aliases exist in `schemas.py` (`AlertReviewRequest`, `AlertNormalizeRequest`, etc.) for legacy references.

5. **State reset after restart**
   - Backend storage is intentionally in-memory; events/mitigations clear on restart.

## 17) Known constraints (for honest report discussion)

- In-memory state only (no persistent DB).
- Single local admin account (not multi-user RBAC).
- Lab-focused enforcement assumptions (bridge naming conventions, local OVS access).
- No full automated test suite currently committed.
- Scenario mode is synthetic by design unless external helper is configured.

## 18) Suggested final-report structure (for Claude to expand)

1. Abstract
2. Problem statement and motivation
3. System architecture
4. ML pipeline and feature engineering
5. Controller integration and telemetry contract
6. Backend API and data model
7. Frontend SOC workflow design
8. Mitigation strategy (manual + automatic)
9. Experimental/demo setup
10. Results and observations
11. Limitations
12. Future work
13. Conclusion

## 19) Copy/paste prompt block for Claude

```text
You are writing a final academic/technical project report.
Use the attached "AI-SDN / smartSDN Project Knowledge File" as the source of truth.

Write a complete, formal report with clear headings, concise technical explanations, and consistent terminology.
Include:
- architecture diagram description in words,
- implementation details across controller/backend/frontend,
- mitigation logic and enforcement details,
- scenario mode vs real ML mode distinction,
- evaluation/demo workflow,
- key troubleshooting learnings,
- limitations and future enhancements.

Tone: professional, submission-ready, no marketing language.
Output in Markdown.
```

---

If new features are added later, update this file first so future report generation remains accurate.
