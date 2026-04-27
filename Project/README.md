# Intelligent SDN Cyber/SOC Platform with FT-Transformer IDS

This project implements a live SDN cyber/SOC-style security monitoring prototype using:
- **Ryu controller** (OpenFlow 1.3)
- **Mininet** network emulation
- **FT-Transformer** (PyTorch) for multi-class IDS inference
- **FastAPI backend** for live SOC APIs
- **React frontend** with login gate, dynamic topology graph, scenario controls, and mitigation controls

## Project structure

```text
Project/
├── Controller/
│   └── ids_switch.py
├── ml/
│   ├── preprocess.py
│   ├── train_transformer.py
│   ├── evaluate.py
│   └── artifacts/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api.py
│   │   ├── schemas.py
│   │   ├── mode.py
│   │   ├── scenario.py
│   │   ├── store.py
│   │   └── mitigation.py
└── frontend/
    ├── src/App.jsx
    ├── src/LoginGate.jsx
    └── package.json
```

## 1) Setup

From the repository root:

```bash
cd Project
python3 -m pip install -r requirements.txt
```

## 2) Prepare data

Place the InSDN-2022 CSV in `Project/data/` (default expected file: `InSDN-2022.csv`), then run:

```bash
python3 -m ml.preprocess --input-csv data/InSDN-2022.csv --output-csv data/InSDN_prepared.csv
```

This creates:
- `data/InSDN_prepared.csv`
- `ml/artifacts/scaler.joblib`
- `ml/artifacts/encoder.joblib`
- `ml/artifacts/feature_schema.json`

## 3) Train FT-Transformer

```bash
python3 -m ml.train_transformer --prepared-csv data/InSDN_prepared.csv --epochs 30 --batch-size 256
```

This saves:
- `ml/artifacts/model.pth`

## 4) Evaluate model

```bash
python3 -m ml.evaluate --prepared-csv data/InSDN_prepared.csv --model-path ml/artifacts/model.pth
```

Outputs:
- accuracy
- classification report
- confusion matrix
- `ml/artifacts/confusion_matrix.png`

## 5) Start Ryu IDS controller

Run from `Project/`:

```bash
ryu-manager Controller/ids_switch.py
```

The controller:
- behaves as a learning switch
- polls flow stats every 2 seconds
- performs inference per flow
- posts classified events to backend `POST /events`
- posts controller health to backend `POST /controller/status`
- remains IDS-only for forwarding behavior (mitigation is managed in backend/UI control plane)

Optional controller backend target override:

```bash
IDS_BACKEND_EVENTS_URL=http://127.0.0.1:8000/events ryu-manager Controller/ids_switch.py
```

Optional status endpoint override:

```bash
IDS_BACKEND_CONTROLLER_STATUS_URL=http://127.0.0.1:8000/controller/status ryu-manager Controller/ids_switch.py
```

## 6) Launch Mininet (OpenFlow 1.3)

In a separate terminal:

```bash
sudo mn --topo single,3 --mac --switch ovsk,protocols=OpenFlow13 --controller remote
```

Optional quick traffic generation from Mininet CLI:

```bash
mininet> pingall
mininet> iperf h1 h2
```

## 7) Start backend API (FastAPI)

From `Project/`:

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Available endpoints:
- `GET /health`
- `GET /mode`
- `PUT /mode`
- `GET /controller/status`
- `POST /controller/status`
- `GET /flows`
- `GET /alerts`
- `GET /sessions`
- `GET /topology`
- `GET /stats`
- `GET /scenarios`
- `POST /scenarios/run`
- `POST /scenarios/clear`
- `GET /mitigation/config`
- `PUT /mitigation/config`
- `GET /mitigation/events`
- `POST /events`
- `POST /mitigate`

## 8) Start frontend dashboard (React)

In another terminal:

```bash
cd Project/frontend
npm install
npm run dev
```

The dashboard defaults to `http://localhost:8000` for backend API calls.
You can override with `VITE_API_BASE_URL` if needed.

## 9) End-to-end demo sequence

Use separate terminals:
1. `ryu-manager Controller/ids_switch.py`
2. `python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload`
3. `cd frontend && npm run dev`
4. `sudo mn --topo single,3 --mac --switch ovsk,protocols=OpenFlow13 --controller remote`
5. Generate traffic (`pingall`, `iperf`) and view dashboard at the Vite URL (default `http://localhost:5173`)

### UI flow
1. Open frontend URL and sign in via the UI login gate.
2. Start in **REAL ML MODE** to show live controller inference labels (`classification_source=ml`).
3. Switch to **DEMO / SCENARIO MODE** to run controlled scenarios:
   - Normal TCP
   - Normal UDP
   - Congestion
   - DoS/DDoS
   - Other Attack
4. Use **Clear / Reset Demo State** to remove scenario-generated events.
5. Demonstrate mitigation from:
   - alerts panel
   - session/conversation cards
   - manual mitigation panel
6. Enable optional automatic mitigation in mitigation config (disabled by default).

## Notes

- Training/runtime feature parity is enforced via `ml/artifacts/feature_schema.json`.
- Runtime features are extracted only from flow statistics and OpenFlow match fields.
- Real ML controller inference is never silently faked.
- Demo/scenario events are explicitly labeled (`classification_source=demo|hybrid`, `mode=DEMO_SCENARIO`).
- Backend store is in-memory only (live events; no persistent history).
- Mitigation is explainable and tracked via live mitigation event logs, isolated from forwarding logic.

