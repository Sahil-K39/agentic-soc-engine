"""
models.py — Pydantic v2 schemas for the Cyber Threat Dashboard.

Used by both app.py (log parsing validation) and agent_platform.py
(mitigation report serialisation).
"""

from pydantic import BaseModel, IPvAnyAddress
from typing import Literal, Optional


class LogEntry(BaseModel):
    """A single parsed log event returned by /api/logs."""
    timestamp: str
    host: str
    service: str
    ip: IPvAnyAddress
    user: Optional[str] = None
    port: Optional[int] = None
    status: Literal["SUCCESS", "FAILURE", "BLOCKED", "ATTACK", "SYSTEM"]
    message: str
    threat_level: Literal["Low", "Medium", "High", "Critical", "Mitigated"]
    country: str
    cc: str
    lat: float
    lon: float


class MitigationReport(BaseModel):
    """
    Structured output written by agent_platform.py to mitigation_report.json.
    Also served by app.py at /mitigation_report.json.
    """
    status: str           # e.g. "Active Threat", "Mitigated", "No Threat"
    ip: str               # keep as str so agent can write "0.0.0.0" freely
    vector: str
    mitre_id: str
    patch_command: str
