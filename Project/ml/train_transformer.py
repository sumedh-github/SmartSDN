"""Train FT-Transformer for 4-class SDN traffic classification."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from ml.config import (
    ENCODER_PATH,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    MODEL_PATH,
    PREPARED_DATA_PATH,
    RANDOM_STATE,
    TEST_SIZE,
)
from ml.model import FTTransformer, FTTransformerConfig
from ml.preprocess import preprocess


LOGGER = logging.getLogger("train")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train FT-Transformer model.")
    parser.add_argument("--prepared-csv", type=Path, default=PREPARED_DATA_PATH)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--d-token", type=int, default=64)
    parser.add_argument("--n-heads", type=int, default=8)
    parser.add_argument("--n-layers", type=int, default=3)
    parser.add_argument("--ffn-dim", type=int, default=128)
    parser.add_argument("--dropout", type=float, default=0.1)
    return parser.parse_args()


def load_prepared_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        LOGGER.info("Prepared dataset not found. Running preprocessing first.")
        preprocess_output, _, _ = preprocess(
            input_csv=Path(path).with_name("InSDN-2022.csv"),
            output_csv=path,
        )
        return preprocess_output
    return pd.read_csv(path)


def build_train_test_tensors(df: pd.DataFrame) -> Tuple[TensorDataset, TensorDataset]:
    if "label_encoded" in df.columns:
        y = df["label_encoded"].astype(np.int64).to_numpy()
    elif LABEL_COLUMN in df.columns:
        encoder = joblib.load(ENCODER_PATH)
        y = encoder.transform(df[LABEL_COLUMN].astype(str)).astype(np.int64)
    else:
        raise ValueError("Prepared CSV must include 'label_encoded' or label column.")

    X = df[FEATURE_COLUMNS].astype(np.float32).to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    train_ds = TensorDataset(
        torch.from_numpy(X_train).float(),
        torch.from_numpy(y_train).long(),
    )
    test_ds = TensorDataset(
        torch.from_numpy(X_test).float(),
        torch.from_numpy(y_test).long(),
    )
    return train_ds, test_ds


def evaluate_epoch(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> Tuple[float, float]:
    model.eval()
    total_loss = 0.0
    total_correct = 0
    total_samples = 0

    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss = criterion(logits, yb)
            preds = torch.argmax(logits, dim=1)

            total_loss += loss.item() * xb.size(0)
            total_correct += (preds == yb).sum().item()
            total_samples += xb.size(0)

    avg_loss = total_loss / max(total_samples, 1)
    accuracy = total_correct / max(total_samples, 1)
    return avg_loss, accuracy


def build_checkpoint(
    cfg: FTTransformerConfig,
    state_dict: dict,
    encoder,
) -> dict:
    clean_config = {
        "num_features": int(cfg.num_features),
        "num_classes": int(cfg.num_classes),
        "d_token": int(cfg.d_token),
        "n_heads": int(cfg.n_heads),
        "n_layers": int(cfg.n_layers),
        "ffn_dim": int(cfg.ffn_dim),
        "dropout": float(cfg.dropout),
        "head_hidden_dim": int(cfg.head_hidden_dim),
    }

    cpu_state_dict = {k: v.detach().cpu() for k, v in state_dict.items()}

    return {
        "model_config": clean_config,
        "state_dict": cpu_state_dict,
        "feature_columns": [str(col) for col in FEATURE_COLUMNS],
        "classes": [str(cls_name) for cls_name in encoder.classes_],
    }


def train(args: argparse.Namespace) -> None:
    device = torch.device("cpu")
    torch.manual_seed(RANDOM_STATE)
    np.random.seed(RANDOM_STATE)

    df = load_prepared_data(args.prepared_csv)
    train_ds, test_ds = build_train_test_tensors(df)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False)

    encoder = joblib.load(ENCODER_PATH)
    num_classes = len(encoder.classes_)

    cfg = FTTransformerConfig(
        num_features=len(FEATURE_COLUMNS),
        num_classes=num_classes,
        d_token=args.d_token,
        n_heads=args.n_heads,
        n_layers=args.n_layers,
        ffn_dim=args.ffn_dim,
        dropout=args.dropout,
    )

    model = FTTransformer(cfg).to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=args.learning_rate,
        weight_decay=args.weight_decay,
    )

    best_acc = -1.0
    best_state = None

    for epoch in range(1, args.epochs + 1):
        model.train()
        running_loss = 0.0
        running_correct = 0
        running_total = 0

        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)

            optimizer.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()

            preds = torch.argmax(logits, dim=1)
            running_loss += loss.item() * xb.size(0)
            running_correct += (preds == yb).sum().item()
            running_total += xb.size(0)

        train_loss = running_loss / max(running_total, 1)
        train_acc = running_correct / max(running_total, 1)
        val_loss, val_acc = evaluate_epoch(model, test_loader, criterion, device)

        LOGGER.info(
            "Epoch %d/%d | train_loss=%.4f train_acc=%.4f | val_loss=%.4f val_acc=%.4f",
            epoch,
            args.epochs,
            train_loss,
            train_acc,
            val_loss,
            val_acc,
        )

        if val_acc > best_acc:
            best_acc = val_acc
            best_state = {k: v.detach().cpu() for k, v in model.state_dict().items()}

    final_state = best_state if best_state is not None else model.state_dict()
    checkpoint = build_checkpoint(cfg, final_state, encoder)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(checkpoint, MODEL_PATH)
    LOGGER.info("Saved best model to %s (best_val_acc=%.4f)", MODEL_PATH, best_acc)


if __name__ == "__main__":
    setup_logging()
    train(parse_args())