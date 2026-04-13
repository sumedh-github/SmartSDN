"""Central configuration for data prep, modeling, and runtime inference."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
ARTIFACT_DIR = PROJECT_ROOT / "ml" / "artifacts"

# Input can be overridden by CLI argument in preprocess.py.
RAW_DATA_PATH = DATA_DIR / "InSDN-2022.csv"
PREPARED_DATA_PATH = DATA_DIR / "InSDN_prepared.csv"

SCALER_PATH = ARTIFACT_DIR / "scaler.joblib"
ENCODER_PATH = ARTIFACT_DIR / "encoder.joblib"
FEATURE_SCHEMA_PATH = ARTIFACT_DIR / "feature_schema.json"
MODEL_PATH = ARTIFACT_DIR / "model.pth"

RANDOM_STATE = 42
TEST_SIZE = 0.20

# These are the exact features used for both offline training and runtime
# inference in the SDN controller.
FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration_sec",
    "packets_per_second",
    "bytes_per_second",
    "avg_bytes_per_packet",
    "src_port",
    "dst_port",
    "protocol",
    "port_gap",
]

LABEL_COLUMN = "label_4class"

# Flexible column aliases to support slight CSV naming differences.
SOURCE_COLUMN_ALIASES = {
    "packet_count": ["packet_count", "pkt_count", "total_packets", "tot_pkts"],
    "byte_count": ["byte_count", "total_bytes", "tot_bytes", "flow_bytes"],
    "duration_sec": [
        "duration_sec",
        "flow_duration_sec",
        "duration",
        "flow_duration",
        "flow_duration_s",
    ],
    "duration_ms": ["duration_ms", "flow_duration_ms"],
    "src_port": ["src_port", "sport", "source_port", "srcport"],
    "dst_port": ["dst_port", "dport", "destination_port", "dstport"],
    "protocol": ["protocol", "proto", "ip_proto"],
}

LABEL_ALIASES = ["label", "attack", "target", "class", "traffic_label"]

NORMAL_KEYWORDS = {"normal", "benign", "legitimate"}
CONGESTION_KEYWORDS = {"congestion", "congested", "queue", "bottleneck"}
DOS_DDOS_KEYWORDS = {
    "dos",
    "ddos",
    "syn_flood",
    "udp_flood",
    "http_flood",
    "hulk",
    "slowloris",
    "goldeneye",
    "smurf",
    "land",
    "teardrop",
}

OUTPUT_CLASSES = ["Normal", "Congestion", "DoS_DDoS", "Other_Attack"]

