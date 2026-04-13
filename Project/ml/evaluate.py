"""Evaluate trained FT-Transformer on held-out traffic flows."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import torch
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from ml.config import (
    ENCODER_PATH,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    MODEL_PATH,
    PREPARED_DATA_PATH,
    RANDOM_STATE,
    TEST_SIZE,
)
from ml.model import FTTransformer


LOGGER = logging.getLogger("evaluate")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate FT-Transformer model.")
    parser.add_argument("--prepared-csv", type=Path, default=PREPARED_DATA_PATH)
    parser.add_argument("--model-path", type=Path, default=MODEL_PATH)
    parser.add_argument("--save-cm", type=Path, default=Path("ml/artifacts/confusion_matrix.png"))
    return parser.parse_args()


def main(args: argparse.Namespace) -> None:
    df = pd.read_csv(args.prepared_csv)
    encoder = joblib.load(ENCODER_PATH)

    if "label_encoded" in df.columns:
        y = df["label_encoded"].astype(np.int64).to_numpy()
    elif LABEL_COLUMN in df.columns:
        y = encoder.transform(df[LABEL_COLUMN].astype(str)).astype(np.int64)
    else:
        raise ValueError("Prepared CSV must include 'label_encoded' or label column.")

    X = df[FEATURE_COLUMNS].astype(np.float32).to_numpy()
    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    checkpoint = torch.load(args.model_path, map_location="cpu")
    model = FTTransformer.from_checkpoint(checkpoint, map_location="cpu")

    with torch.no_grad():
        logits = model(torch.from_numpy(X_test).float())
        y_pred = torch.argmax(logits, dim=1).cpu().numpy()

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test,
        y_pred,
        target_names=encoder.classes_,
        digits=4,
    )
    cm = confusion_matrix(y_test, y_pred)

    LOGGER.info("Accuracy: %.4f", acc)
    LOGGER.info("Classification report:\n%s", report)
    LOGGER.info("Confusion matrix:\n%s", cm)

    args.save_cm.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=encoder.classes_,
        yticklabels=encoder.classes_,
    )
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title("FT-Transformer Confusion Matrix")
    plt.tight_layout()
    plt.savefig(args.save_cm)
    LOGGER.info("Saved confusion matrix figure to %s", args.save_cm)


if __name__ == "__main__":
    setup_logging()
    main(parse_args())

