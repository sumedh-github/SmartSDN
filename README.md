# Intelligent SDN Cyber/SOC Platform with FT-Transformer IDS

This repository contains a Linux/Kali-compatible research/demo SDN security platform with:
- **Ryu controller** (OpenFlow 1.3 learning switch + live FT-Transformer inference)
- **Mininet/OVS lab traffic**
- **FastAPI backend** (auth, topology ownership, sessions, scenarios, mitigation contracts)
- **React frontend** (protected routes, SOC dashboard sections, topology graph, explainability)

## Current architecture (source of truth)

```text
Project/
├── Controller/
│   └── ids_switch.py                    # Live flow polling + FT-Transformer inference
├── ml/
│   ├── preprocess.py
│   ├── train_transformer.py
│   ├── evaluate.py
│   └── artifacts/                       # model/scaler/encoder/schema
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api.py                       # /auth, /topology, /flows, /sessions, /mitigations...
│   │   ├── auth.py                      # single-admin token auth service
│   │   ├── enforcement.py               # OVS/Mininet mitigation enforcement
│   │   ├── schemas.py
│   │   ├── mode.py
│   │   ├── scenario.py
│   │   ├── store.py
│   │   └── mitigation.py
│   └── README.md
└── frontend/
    ├── src/App.jsx                      # protected multi-section SOC dashboard
    ├── src/LoginGate.jsx
    └── package.json
```

## 1) Install dependencies

```bash
cd Project
python3 -m pip install -r requirements.txt
cd frontend && npm install && cd ..
```

## 2) Data prep / training / evaluation (unchanged ML pipeline)

```bash
python3 -m ml.preprocess --input-csv data/InSDN-2022.csv --output-csv data/InSDN_prepared.csv
python3 -m ml.train_transformer --prepared-csv data/InSDN_prepared.csv --epochs 30 --batch-size 256
python3 -m ml.evaluate --prepared-csv data/InSDN_prepared.csv --model-path ml/artifacts/model.pth
```

## 3) Configure backend auth/enforcement (optional env overrides)

Defaults are local/demo friendly, but you can set:

```bash
export SOC_ADMIN_USERNAME=admin
export SOC_ADMIN_EMAIL=admin@localhost
export SOC_ADMIN_PASSWORD=admin1234
export SOC_AUTH_SECRET="change-this-local-secret"
export SOC_AUTH_TOKEN_TTL_SEC=28800

export SOC_ENFORCEMENT_ENABLED=true
export SOC_OVS_OFCTL_BIN=ovs-ofctl
export SOC_OVS_BRIDGE_PREFIX=s

# Optional real scenario helper command:
# export SOC_SCENARIO_HELPER_CMD="python3 /path/to/scenario_helper.py"
```

## 4) Start backend, controller, frontend, and Mininet

Use separate terminals:

1. **Backend**
   ```bash
   cd Project
   python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

2. **Ryu controller**
   ```bash
   cd Project
   ryu-manager Controller/ids_switch.py
   ```

3. **Frontend**
   ```bash
   cd Project/frontend
   npm run dev
   ```

4. **Mininet**
   ```bash
   sudo mn --topo single,3 --mac --switch ovsk,protocols=OpenFlow13 --controller remote
   ```

## 5) Backend API contracts

### Auth
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`

### Monitoring / topology / sessions
- `GET /health`
- `GET /mode`, `PUT /mode`
- `GET /controller/status`, `POST /controller/status`
- `POST /events`
- `GET /flows`
- `GET /sessions`
- `GET /alerts`
- `GET /stats`
- `GET /topology`

### Scenarios
- `GET /scenarios`
- `POST /scenarios/run`
- `POST /scenarios/reset` (and `POST /scenarios/clear` compatibility)

### Mitigation
- `GET /mitigation/config`, `PUT /mitigation/config`
- `GET /mitigation/events`
- `POST /mitigations/apply`
- `POST /mitigations/retract`
- `GET /mitigations/active`
- `POST /mitigate` (legacy compatibility alias)

## 6) Demo guide (professor/portfolio flow)

1. Open frontend URL (default `http://localhost:5173`) and **log in** with backend-configured admin credentials.
2. Verify section navigation:
   - Overview Dashboard
   - Topology
   - Raw Flows
   - Sessions
   - Alerts
   - Scenarios
   - Mitigation
   - System / Controller Health
   - Methodology / About
3. Generate real traffic in Mininet (`pingall`, `iperf h1 h2`) and show **REAL ML MODE** inference (`label_source=ml`).
4. Switch to **DEMO / SCENARIO MODE** and run:
   - Normal TCP
   - Normal UDP
   - Congestion
   - DoS_DDoS
   - Other_Attack
   with host targeting + intensity/concurrency controls.
5. Show **grouped sessions** as primary operational view and compare with raw directional flows.
6. Perform manual mitigation:
   - Block Flow Pair (`src_ip + dst_ip + protocol`)
   - Block Source Host (IPv4 only, ARP not blocked by default)
   - Disable / Isolate Port
7. Enable automatic mitigation (disabled by default), demonstrate explainable trigger metadata.
8. Use rollback via active mitigation table:
   - unblock source host
   - unblock flow pair
   - re-enable port
9. Validate real enforcement in Mininet:
   - blocked pair/source should fail for IP traffic
   - isolated port should impact connectivity
   - rollback should restore connectivity

## 7) UI explainability indicators

- **Mode banner:** `REAL ML MODE` or `DEMO / SCENARIO MODE`
- **Label source badges:** `ML`, `Demo`, `Hybrid`
- **Mitigation source:** `manual` or `automatic`
- **Topology legend:** normal / suspicious / blocked traffic, disabled link/port, node type colors
- **Methodology panel:** explicit definitions and caveats (including why synthetic traffic can still classify as Normal in real ML mode)

## Notes

- Training/runtime feature alignment is preserved via `ml/artifacts/feature_schema.json`.
- Real controller ML output is never silently faked.
- Demo/scenario events remain explicitly marked (`classification_source=demo|hybrid`, `mode=DEMO_SCENARIO`).
- Runtime state is in-memory by design (resets cleanly on backend restart).
