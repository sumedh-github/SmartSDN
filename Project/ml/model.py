"""FT-Transformer model for tabular flow classification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import torch
import torch.nn as nn


@dataclass
class FTTransformerConfig:
    num_features: int
    num_classes: int
    d_token: int = 64
    n_heads: int = 8
    n_layers: int = 3
    ffn_dim: int = 128
    dropout: float = 0.1
    head_hidden_dim: int = 128


class NumericalFeatureTokenizer(nn.Module):
    """
    Converts each scalar feature into a learnable token embedding.
    """

    def __init__(self, num_features: int, d_token: int) -> None:
        super().__init__()
        self.num_features = num_features
        self.d_token = d_token
        self.weight = nn.Parameter(torch.empty(num_features, d_token))
        self.bias = nn.Parameter(torch.empty(num_features, d_token))
        self.reset_parameters()

    def reset_parameters(self) -> None:
        nn.init.xavier_uniform_(self.weight)
        nn.init.zeros_(self.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: [batch, num_features]
        if x.ndim != 2 or x.size(1) != self.num_features:
            raise ValueError(
                f"Expected input shape [batch, {self.num_features}], got {tuple(x.shape)}"
            )
        return x.unsqueeze(-1) * self.weight.unsqueeze(0) + self.bias.unsqueeze(0)


class FTTransformer(nn.Module):
    def __init__(self, cfg: FTTransformerConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self.tokenizer = NumericalFeatureTokenizer(cfg.num_features, cfg.d_token)
        self.cls_token = nn.Parameter(torch.zeros(1, 1, cfg.d_token))

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=cfg.d_token,
            nhead=cfg.n_heads,
            dim_feedforward=cfg.ffn_dim,
            dropout=cfg.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=cfg.n_layers)

        self.classifier = nn.Sequential(
            nn.LayerNorm(cfg.d_token),
            nn.Linear(cfg.d_token, cfg.head_hidden_dim),
            nn.GELU(),
            nn.Dropout(cfg.dropout),
            nn.Linear(cfg.head_hidden_dim, cfg.num_classes),
        )

    def forward(self, x: torch.Tensor, return_proba: bool = False) -> torch.Tensor:
        tokens = self.tokenizer(x)
        cls = self.cls_token.expand(x.size(0), -1, -1)
        x_seq = torch.cat([cls, tokens], dim=1)
        encoded = self.encoder(x_seq)
        cls_repr = encoded[:, 0]
        logits = self.classifier(cls_repr)
        if return_proba:
            return torch.softmax(logits, dim=-1)
        return logits

    @staticmethod
    def from_checkpoint(checkpoint: Dict[str, object], map_location: str | torch.device = "cpu") -> "FTTransformer":
        cfg = FTTransformerConfig(**checkpoint["model_config"])
        model = FTTransformer(cfg)
        model.load_state_dict(checkpoint["state_dict"])
        model.to(map_location)
        model.eval()
        return model

