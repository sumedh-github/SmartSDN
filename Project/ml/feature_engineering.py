"""Feature extraction utilities shared by training and runtime inference."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, Iterable, Optional

import numpy as np
import pandas as pd

from ml.config import FEATURE_COLUMNS, OUTPUT_CLASSES

logger = logging.getLogger(__name__)

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


def _extract_packet_count(df: pd.DataFrame) -> pd.Series:
    """
    Build packet_count from either:
    - a direct runtime-style column, or
    - Tot Fwd Pkts + Tot Bwd Pkts
    """
    direct_col = _first_existing(df, ["packet_count"])
    if direct_col is not None:
        logger.info("Using direct packet_count column: %s", direct_col)
        return _to_numeric(df[direct_col], fill_value=0.0)

    fwd_col = _first_existing(df, ["tot_fwd_pkts", "total_fwd_packets"])
    bwd_col = _first_existing(df, ["tot_bwd_pkts", "total_backward_packets"])

    if fwd_col is not None and bwd_col is not None:
        logger.info("Building packet_count from %s + %s", fwd_col, bwd_col)
        return _to_numeric(df[fwd_col], fill_value=0.0) + _to_numeric(df[bwd_col], fill_value=0.0)

    raise ValueError(
        "Could not build packet_count. Expected either 'packet_count' or "
        "both 'tot_fwd_pkts' and 'tot_bwd_pkts'."
    )


def _extract_byte_count(df: pd.DataFrame) -> pd.Series:
    """
    Build byte_count from either:
    - a direct runtime-style column, or
    - TotLen Fwd Pkts + TotLen Bwd Pkts
    """
    direct_col = _first_existing(df, ["byte_count"])
    if direct_col is not None:
        logger.info("Using direct byte_count column: %s", direct_col)
        return _to_numeric(df[direct_col], fill_value=0.0)

    fwd_len_col = _first_existing(
        df,
        [
            "totlen_fwd_pkts",
            "total_length_of_fwd_packets",
            "fwd_packet_length_total",
        ],
    )
    bwd_len_col = _first_existing(
        df,
        [
            "totlen_bwd_pkts",
            "total_length_of_bwd_packets",
            "bwd_packet_length_total",
        ],
    )

    if fwd_len_col is not None and bwd_len_col is not None:
        logger.info("Building byte_count from %s + %s", fwd_len_col, bwd_len_col)
        return _to_numeric(df[fwd_len_col], fill_value=0.0) + _to_numeric(df[bwd_len_col], fill_value=0.0)

    raise ValueError(
        "Could not build byte_count. Expected either 'byte_count' or "
        "both 'totlen_fwd_pkts' and 'totlen_bwd_pkts'."
    )


def _extract_duration_sec(df: pd.DataFrame) -> pd.Series:
    """
    Build duration_sec from either:
    - direct runtime-style duration_sec,
    - duration_ms,
    - or Flow Duration from InSDN, usually in microseconds.
    """
    duration_sec_col = _first_existing(df, ["duration_sec"])
    if duration_sec_col is not None:
        logger.info("Using direct duration_sec column: %s", duration_sec_col)
        return _to_numeric(df[duration_sec_col], fill_value=0.0).clip(lower=0.0)

    duration_ms_col = _first_existing(df, ["duration_ms"])
    if duration_ms_col is not None:
        logger.info("Building duration_sec from duration_ms")
        return (_to_numeric(df[duration_ms_col], fill_value=0.0) / 1000.0).clip(lower=0.0)

    flow_duration_col = _first_existing(df, ["flow_duration"])
    if flow_duration_col is not None:
        logger.info("Building duration_sec from flow_duration (assumed microseconds)")
        raw = _to_numeric(df[flow_duration_col], fill_value=0.0).clip(lower=0.0)
        return (raw / 1_000_000.0).clip(lower=0.0)

    raise ValueError(
        "Could not build duration_sec. Expected one of: "
        "'duration_sec', 'duration_ms', or 'flow_duration'."
    )


def _extract_src_port(df: pd.DataFrame) -> pd.Series:
    col = _first_existing(df, ["src_port"])
    if col is not None:
        return _to_numeric(df[col], fill_value=0.0)
    logger.warning("No source port column found. Filling src_port with 0.")
    return pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)


def _extract_dst_port(df: pd.DataFrame) -> pd.Series:
    col = _first_existing(df, ["dst_port"])
    if col is not None:
        return _to_numeric(df[col], fill_value=0.0)
    logger.warning("No destination port column found. Filling dst_port with 0.")
    return pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)


def _extract_protocol(df: pd.DataFrame) -> pd.Series:
    col = _first_existing(df, ["protocol"])
    if col is not None:
        return _to_numeric(df[col], fill_value=0.0)
    logger.warning("No protocol column found. Filling protocol with 0.")
    return pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)


def _extract_base_runtime_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract canonical runtime columns from raw training data.
    """
    out = pd.DataFrame(index=df.index)

    out["packet_count"] = _extract_packet_count(df)
    out["byte_count"] = _extract_byte_count(df)
    out["duration_sec"] = _extract_duration_sec(df)
    out["src_port"] = _extract_src_port(df)
    out["dst_port"] = _extract_dst_port(df)
    out["protocol"] = _extract_protocol(df)

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
    base["port_gap"] = (base["src_port"] - base["dst_port"]).abs()

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