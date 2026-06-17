from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models import utc_now
from app.risk_scoring import RiskLevel


TOOL_CALL_ACTION_FIELDS: tuple[str, ...] = (
    "action_type",
    "tool_name",
    "arguments",
    "risk_level",
    "source_context_ids",
    "timestamp",
)


class ToolCallAction(BaseModel):
    action_type: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel
    source_context_ids: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("action_type", "tool_name")
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tool-call action type and tool name must not be blank.")
        return value

    @field_validator("source_context_ids")
    @classmethod
    def _source_context_ids_must_not_be_blank(cls, value: list[str]) -> list[str]:
        if any(not context_id.strip() for context_id in value):
            raise ValueError("source context ids must not be blank.")
        return value
