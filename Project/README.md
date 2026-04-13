# Intelligent SDN Controller with FT-Transformer IDS

This project implements real-time SDN traffic classification using:
- **Ryu controller** (OpenFlow 1.3)
- **Mininet** network emulation
- **FT-Transformer** (PyTorch) for multi-class IDS inference

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

## Notes

- Training/runtime feature parity is enforced via `ml/artifacts/feature_schema.json`.
- Runtime features are extracted only from flow statistics and OpenFlow match fields.
- The controller is IDS-only by design (detection, not mitigation).

