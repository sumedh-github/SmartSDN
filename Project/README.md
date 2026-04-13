# Intelligent SDN Controller with FT-Transformer IDS

This project implements real-time SDN traffic classification using:
- **Ryu controller** (OpenFlow 1.3)
- **Mininet** network emulation
- **FT-Transformer** (PyTorch) for multi-class IDS inference

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
│   │   └── store.py
│   └── data/sample_events.json
└── frontend/
    ├── src/App.jsx
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
- polls flow stats every 5 seconds
- performs inference per flow
- logs detection alerts only (no blocking)

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
- `GET /flows`
- `GET /alerts`
- `GET /stats`

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

## Notes

- Training/runtime feature parity is enforced via `ml/artifacts/feature_schema.json`.
- Runtime features are extracted only from flow statistics and OpenFlow match fields.
- The controller is IDS-only by design (detection, not mitigation).
- Backend and frontend are intentionally decoupled from Ryu internals. The current backend loads sample JSON data and is ready to receive real events later.

## Future controller event emission (not required for this phase)

To feed live events into the backend later, update `Controller/ids_switch.py` minimally by:
1. Building an event payload after each successful classification (`timestamp`, flow tuple, prediction, confidence, counters).
2. Sending that payload to a backend ingest interface (e.g., POST endpoint or local queue) in a non-blocking way.
3. Keeping classification logic and feature schema unchanged.

