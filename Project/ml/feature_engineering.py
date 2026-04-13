"""Feature extraction utilities shared by training and runtime inference."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, Optional

import numpy as np
import pandas as pd

from ml.config import FEATURE_COLUMNS, OUTPUT_CLASSES, SOURCE_COLUMN_ALIASES

EPS = 1e-6


def canonicalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize CSV columns to snake_case for robust matching."""
    renamed = {}
    for col in df.columns:
        col_norm = re.sub(r"[^a-zA-Z0-9]+", "_", str(col).strip().lower()).strip("_")
        renamed[col] = col_norm
    return df.rename(columns=renamed)


def _first_existing(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    for col in candidates:
        if col in df.columns:
            return col
    return None


def _to_numeric(series: pd.Series, fill_value: float = 0.0) -> pd.Series:
    out = pd.to_numeric(series, errors="coerce")
    out = out.replace([np.inf, -np.inf], np.nan).fillna(fill_value)
    return out.astype(np.float32)


def _extract_base_runtime_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Extract columns that are directly available in OpenFlow flow stats."""
    out = pd.DataFrame(index=df.index)

    packet_col = _first_existing(df, SOURCE_COLUMN_ALIASES["packet_count"])
    byte_col = _first_existing(df, SOURCE_COLUMN_ALIASES["byte_count"])

    if packet_col is None or byte_col is None:
        missing = []
        if packet_col is None:
            missing.append("packet_count")
        if byte_col is None:
            missing.append("byte_count")
        raise ValueError(f"Required columns not found in dataset: {missing}")

    duration_sec_col = _first_existing(df, SOURCE_COLUMN_ALIASES["duration_sec"])
    duration_ms_col = _first_existing(df, SOURCE_COLUMN_ALIASES["duration_ms"])

    out["packet_count"] = _to_numeric(df[packet_col], fill_value=0.0)
    out["byte_count"] = _to_numeric(df[byte_col], fill_value=0.0)

    if duration_sec_col is not None:
        out["duration_sec"] = _to_numeric(df[duration_sec_col], fill_value=0.0)
    elif duration_ms_col is not None:
        out["duration_sec"] = _to_numeric(df[duration_ms_col], fill_value=0.0) / 1000.0
    else:
        raise ValueError("No duration column found (seconds or milliseconds).")

    src_port_col = _first_existing(df, SOURCE_COLUMN_ALIASES["src_port"])
    dst_port_col = _first_existing(df, SOURCE_COLUMN_ALIASES["dst_port"])
    protocol_col = _first_existing(df, SOURCE_COLUMN_ALIASES["protocol"])

    out["src_port"] = _to_numeric(df[src_port_col], fill_value=0.0) if src_port_col else 0.0
    out["dst_port"] = _to_numeric(df[dst_port_col], fill_value=0.0) if dst_port_col else 0.0
    out["protocol"] = _to_numeric(df[protocol_col], fill_value=0.0) if protocol_col else 0.0

    return out


def build_runtime_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build the exact feature vector used by both training and controller runtime.
    """
    base = _extract_base_runtime_columns(df)
    duration_safe = base["duration_sec"].clip(lower=EPS)
    packet_safe = base["packet_count"].clip(lower=1.0)
    byte_safe = base["byte_count"].clip(lower=1.0)

    base["packets_per_second"] = base["packet_count"] / duration_safe
    base["bytes_per_second"] = base["byte_count"] / duration_safe
    base["avg_bytes_per_packet"] = base["byte_count"] / packet_safe
    base["packet_byte_ratio"] = base["packet_count"] / byte_safe

    feature_df = base[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return feature_df.astype(np.float32)


def export_feature_schema(path: Path) -> Dict[str, object]:
    schema = {
        "feature_columns": FEATURE_COLUMNS,
        "num_features": len(FEATURE_COLUMNS),
        "classes": OUTPUT_CLASSES,
        "notes": "Training and runtime inference must use this exact feature order.",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    return schema

