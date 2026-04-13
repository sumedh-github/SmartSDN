"""Preprocessing pipeline for InSDN traffic classification."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ml.config import (
    ENCODER_PATH,
    FEATURE_SCHEMA_PATH,
    LABEL_ALIASES,
    LABEL_COLUMN,
    NORMAL_KEYWORDS,
    CONGESTION_KEYWORDS,
    DOS_DDOS_KEYWORDS,
    OUTPUT_CLASSES,
    PREPARED_DATA_PATH,
    RANDOM_STATE,
    RAW_DATA_PATH,
    SCALER_PATH,
    TEST_SIZE,
)
from ml.feature_engineering import (
    build_runtime_feature_frame,
    canonicalize_columns,
    export_feature_schema,
)


LOGGER = logging.getLogger("preprocess")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def find_label_column(df: pd.DataFrame) -> str:
    for col in LABEL_ALIASES:
        if col in df.columns:
            return col
    raise ValueError(
        f"No label column found. Tried aliases: {sorted(LABEL_ALIASES)}. "
        f"Available columns: {list(df.columns)}"
    )


def map_label_to_4class(label: object) -> str:
    value = str(label).strip().lower()
    if any(key in value for key in NORMAL_KEYWORDS):
        return "Normal"
    if any(key in value for key in CONGESTION_KEYWORDS):
        return "Congestion"
    if any(key in value for key in DOS_DDOS_KEYWORDS):
        return "DoS_DDoS"
    return "Other_Attack"


def load_dataset(path: Path) -> pd.DataFrame:
    LOGGER.info("Loading dataset from %s", path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    df = pd.read_csv(path, low_memory=False)
    df = canonicalize_columns(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    return df


def fit_scaler_on_train_slice(features: pd.DataFrame, labels: pd.Series) -> StandardScaler:
    indices = np.arange(len(features))
    train_idx, _ = train_test_split(
        indices,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )
    scaler = StandardScaler()
    scaler.fit(features.iloc[train_idx])
    return scaler


def preprocess(input_csv: Path, output_csv: Path) -> Tuple[pd.DataFrame, StandardScaler, LabelEncoder]:
    df = load_dataset(input_csv)
    label_col = find_label_column(df)
    LOGGER.info("Using label column: %s", label_col)

    labels_4class = df[label_col].map(map_label_to_4class)
    features = build_runtime_feature_frame(df)

    scaler = fit_scaler_on_train_slice(features, labels_4class)
    features_scaled = pd.DataFrame(
        scaler.transform(features),
        columns=features.columns,
        index=features.index,
    )

    encoder = LabelEncoder()
    encoder.fit(OUTPUT_CLASSES)
    encoded_labels = encoder.transform(labels_4class)

    prepared = features_scaled.copy()
    prepared[LABEL_COLUMN] = labels_4class
    prepared["label_encoded"] = encoded_labels

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    prepared.to_csv(output_csv, index=False)
    LOGGER.info("Saved prepared dataset to %s (rows=%d)", output_csv, len(prepared))

    SCALER_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(encoder, ENCODER_PATH)
    export_feature_schema(FEATURE_SCHEMA_PATH)
    LOGGER.info("Saved artifacts: %s, %s, %s", SCALER_PATH, ENCODER_PATH, FEATURE_SCHEMA_PATH)

    LOGGER.info("Class distribution:\n%s", labels_4class.value_counts())
    return prepared, scaler, encoder


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preprocess InSDN-2022 dataset.")
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=RAW_DATA_PATH,
        help=f"Path to raw InSDN CSV (default: {RAW_DATA_PATH})",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=PREPARED_DATA_PATH,
        help=f"Path to save prepared CSV (default: {PREPARED_DATA_PATH})",
    )
    return parser.parse_args()


if __name__ == "__main__":
    setup_logging()
    args = parse_args()
    preprocess(args.input_csv, args.output_csv)

