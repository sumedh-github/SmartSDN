"""Runtime mode management for REAL ML vs demo scenarios."""

from __future__ import annotations

from threading import RLock

from backend.app.schemas import ModeType


MODE_DESCRIPTIONS: dict[ModeType, str] = {
    "REAL_ML": "Uses only live controller FT-Transformer inference outputs.",
    "DEMO_SCENARIO": "Allows labeled demo scenarios and hybrid demo logic for presentations.",
}


class ModeService:
    """Thread-safe mode state for API and UI controls."""

    def __init__(self, initial_mode: ModeType = "REAL_ML") -> None:
        self._mode = initial_mode
        self._lock = RLock()

    def get_mode(self) -> ModeType:
        with self._lock:
            return self._mode

    def set_mode(self, mode: ModeType) -> dict[str, str]:
        with self._lock:
            self._mode = mode
        return {"mode": mode, "description": MODE_DESCRIPTIONS[mode]}

    def status(self) -> dict[str, str]:
        with self._lock:
            mode = self._mode
        return {"mode": mode, "description": MODE_DESCRIPTIONS[mode]}
