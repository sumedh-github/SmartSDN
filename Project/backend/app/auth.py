"""Local single-admin authentication service with signed bearer tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(f"{raw}{padding}".encode("utf-8"))


@dataclass(frozen=True)
class AuthUser:
    username: str
    email: str
    role: str = "admin"


class AuthService:
    """Handles local admin login and stateless token validation."""

    def __init__(self) -> None:
        self._username = os.getenv("SOC_ADMIN_USERNAME", "admin")
        self._email = os.getenv("SOC_ADMIN_EMAIL", "admin@localhost")
        self._password = os.getenv("SOC_ADMIN_PASSWORD", "admin1234")
        self._secret = os.getenv("SOC_AUTH_SECRET", "change-this-local-secret")
        self._token_ttl_sec = int(os.getenv("SOC_AUTH_TOKEN_TTL_SEC", "28800"))

    @property
    def token_ttl_sec(self) -> int:
        return self._token_ttl_sec

    def login(self, *, identifier: str, password: str) -> tuple[str, AuthUser, datetime]:
        normalized = identifier.strip().lower()
        if normalized not in {self._username.lower(), self._email.lower()}:
            raise ValueError("Invalid credentials.")
        if not hmac.compare_digest(password, self._password):
            raise ValueError("Invalid credentials.")

        user = AuthUser(username=self._username, email=self._email)
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=self._token_ttl_sec)
        token = self._encode_token(
            {
                "sub": user.username,
                "email": user.email,
                "role": user.role,
                "iat": int(issued_at.timestamp()),
                "exp": int(expires_at.timestamp()),
            }
        )
        return token, user, expires_at

    def validate_token(self, token: str) -> AuthUser:
        payload = self._decode_token(token)
        exp = int(payload.get("exp", 0))
        now = int(datetime.now(timezone.utc).timestamp())
        if exp <= now:
            raise ValueError("Session has expired. Please log in again.")

        username = str(payload.get("sub", "")).strip()
        email = str(payload.get("email", "")).strip()
        role = str(payload.get("role", "admin")).strip() or "admin"
        if not username or not email:
            raise ValueError("Invalid token payload.")
        return AuthUser(username=username, email=email, role=role)

    def _encode_token(self, payload: dict[str, object]) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        encoded_header = _b64url_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        encoded_payload = _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        signature = hmac.new(
            self._secret.encode("utf-8"),
            signing_input,
            digestmod=hashlib.sha256,
        ).digest()
        return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"

    def _decode_token(self, token: str) -> dict[str, object]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token.")
        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        expected_signature = hmac.new(
            self._secret.encode("utf-8"),
            signing_input,
            digestmod=hashlib.sha256,
        ).digest()
        presented_signature = _b64url_decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, presented_signature):
            raise ValueError("Invalid token signature.")
        try:
            payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid token payload.") from exc
        return payload
