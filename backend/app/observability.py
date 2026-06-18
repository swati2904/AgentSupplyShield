import json
from datetime import UTC, datetime
from typing import Any, Literal, TypeAlias
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


LogStatus: TypeAlias = Literal["started", "ok", "error", "blocked", "skipped"]


class TraceContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    trace_id: str
    config_hash: str
    run_id: str | None = None
    source_id: str | None = None

    @field_validator("request_id", "trace_id", "config_hash")
    @classmethod
    def _required_strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("trace context required strings must not be blank.")
        return value

    @field_validator("run_id", "source_id")
    @classmethod
    def _optional_strings_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("trace context optional strings must not be blank.")
        return value


class StructuredLogEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    service: str
    request_id: str
    trace_id: str
    config_hash: str
    run_id: str | None = None
    source_id: str | None = None
    tool_id: str | None = None
    event_type: str
    status: LogStatus
    latency_ms: float = Field(ge=0.0)
    error_code: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", "service", "request_id", "trace_id", "config_hash", "event_type")
    @classmethod
    def _required_strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("structured log required strings must not be blank.")
        return value

    @field_validator("run_id", "source_id", "tool_id", "error_code")
    @classmethod
    def _optional_strings_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("structured log optional strings must not be blank.")
        return value


def new_request_trace_context(
    *,
    config_hash: str,
    request_id: str | None = None,
    trace_id: str | None = None,
) -> TraceContext:
    return TraceContext(
        request_id=request_id or _new_id("req"),
        trace_id=trace_id or _new_id("trace"),
        config_hash=config_hash,
    )


def new_scan_trace_context(
    *,
    run_id: str,
    source_id: str,
    config_hash: str,
    request_id: str | None = None,
    trace_id: str | None = None,
) -> TraceContext:
    return TraceContext(
        request_id=request_id or _new_id("req"),
        trace_id=trace_id or _new_id("trace"),
        run_id=run_id,
        source_id=source_id,
        config_hash=config_hash,
    )


def build_structured_log_event(
    *,
    service: str,
    event_type: str,
    status: LogStatus,
    trace_context: TraceContext,
    latency_ms: float,
    tool_id: str | None = None,
    error_code: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> StructuredLogEvent:
    return StructuredLogEvent(
        timestamp=_utc_timestamp(),
        service=service,
        request_id=trace_context.request_id,
        trace_id=trace_context.trace_id,
        run_id=trace_context.run_id,
        source_id=trace_context.source_id,
        tool_id=tool_id,
        event_type=event_type,
        status=status,
        latency_ms=round(latency_ms, 3),
        error_code=error_code,
        config_hash=trace_context.config_hash,
        metadata=metadata or {},
    )


def structured_log_event_to_json(event: StructuredLogEvent) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"
