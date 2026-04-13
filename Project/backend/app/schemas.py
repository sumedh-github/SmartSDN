"""Pydantic schemas for IDS flow events and API responses."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FlowEvent(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0)
    dst_port: int = Field(ge=0)
    protocol: str
    prediction: str
    confidence: float = Field(ge=0.0, le=1.0)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)


class HealthResponse(BaseModel):
    status: str


class StatsResponse(BaseModel):
    total_flows: int
    normal_flows: int
    suspicious_flows: int
    active_hosts: int
    class_distribution: dict[str, int]
