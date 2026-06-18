import logging
import traceback
from typing import Any, Literal, TypeAlias
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.observability import TraceContext, build_structured_log_event, new_request_trace_context, structured_log_event_to_json


ErrorCategory: TypeAlias = Literal[
    "crawl_error",
    "parse_error",
    "embedding_error",
    "policy_error",
    "sandbox_error",
    "report_error",
    "rate_limit_error",
]

ERROR_CATEGORIES: tuple[str, ...] = (
    "crawl_error",
    "parse_error",
    "embedding_error",
    "policy_error",
    "sandbox_error",
    "report_error",
    "rate_limit_error",
)

ERROR_CATEGORY_DEFAULTS: dict[ErrorCategory, dict[str, Any]] = {
    "crawl_error": {
        "status_code": 502,
        "recoverable": True,
        "retryable": True,
        "user_message": "The source could not be crawled safely. Please retry later or use a local artifact.",
    },
    "parse_error": {
        "status_code": 422,
        "recoverable": True,
        "retryable": False,
        "user_message": "The input could not be parsed. Please check the artifact format and try again.",
    },
    "embedding_error": {
        "status_code": 503,
        "recoverable": True,
        "retryable": True,
        "user_message": "Evidence retrieval is temporarily unavailable. Please retry later.",
    },
    "policy_error": {
        "status_code": 500,
        "recoverable": False,
        "retryable": False,
        "user_message": "The policy decision could not be completed safely.",
    },
    "sandbox_error": {
        "status_code": 500,
        "recoverable": True,
        "retryable": True,
        "user_message": "The sandbox run could not be completed. Please retry with the same mock inputs.",
    },
    "report_error": {
        "status_code": 500,
        "recoverable": False,
        "retryable": False,
        "user_message": "The report could not be generated safely.",
    },
    "rate_limit_error": {
        "status_code": 429,
        "recoverable": True,
        "retryable": True,
        "user_message": "The request was rate limited. Please retry after a short delay.",
    },
}


class AgentSupplyShieldError(Exception):
    def __init__(
        self,
        *,
        category: ErrorCategory,
        error_code: str,
        user_message: str | None = None,
        internal_message: str | None = None,
        status_code: int | None = None,
        recoverable: bool | None = None,
        retryable: bool | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        defaults = ERROR_CATEGORY_DEFAULTS[category]
        self.category = category
        self.error_code = error_code
        self.user_message = user_message or str(defaults["user_message"])
        self.internal_message = internal_message or self.user_message
        self.status_code = status_code or int(defaults["status_code"])
        self.recoverable = bool(defaults["recoverable"] if recoverable is None else recoverable)
        self.retryable = bool(defaults["retryable"] if retryable is None else retryable)
        self.context = context or {}
        super().__init__(self.internal_message)


class ErrorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error_id: str
    category: ErrorCategory
    error_code: str
    recoverable: bool
    retryable: bool
    user_message: str
    internal_message: str
    internal_stack_trace: list[str]
    status_code: int = Field(ge=400, le=599)
    request_id: str
    trace_id: str
    config_hash: str
    run_id: str | None = None
    source_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "error_id",
        "error_code",
        "user_message",
        "internal_message",
        "request_id",
        "trace_id",
        "config_hash",
    )
    @classmethod
    def _required_strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("error record required strings must not be blank.")
        return value

    @field_validator("run_id", "source_id")
    @classmethod
    def _optional_strings_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("error record optional strings must not be blank.")
        return value


class ErrorResponseDetail(BaseModel):
    category: ErrorCategory
    error_code: str
    recoverable: bool
    retryable: bool
    message: str
    request_id: str
    trace_id: str
    run_id: str | None = None
    source_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorResponseDetail


def build_error_record(error: Exception, *, trace_context: TraceContext) -> ErrorRecord:
    if isinstance(error, AgentSupplyShieldError):
        category = error.category
        error_code = error.error_code
        status_code = error.status_code
        recoverable = error.recoverable
        retryable = error.retryable
        user_message = error.user_message
        internal_message = error.internal_message
        context = error.context
    else:
        defaults = ERROR_CATEGORY_DEFAULTS["report_error"]
        category = "report_error"
        error_code = "unhandled_exception"
        status_code = int(defaults["status_code"])
        recoverable = bool(defaults["recoverable"])
        retryable = bool(defaults["retryable"])
        user_message = str(defaults["user_message"])
        internal_message = str(error)
        context = {}

    return ErrorRecord(
        error_id=f"err_{uuid4().hex}",
        category=category,
        error_code=error_code,
        recoverable=recoverable,
        retryable=retryable,
        user_message=user_message,
        internal_message=internal_message,
        internal_stack_trace=traceback.format_exception(type(error), error, error.__traceback__),
        status_code=status_code,
        request_id=trace_context.request_id,
        trace_id=trace_context.trace_id,
        run_id=trace_context.run_id,
        source_id=trace_context.source_id,
        config_hash=trace_context.config_hash,
        context=context,
    )


def build_error_response(record: ErrorRecord) -> ErrorResponse:
    return ErrorResponse(
        error=ErrorResponseDetail(
            category=record.category,
            error_code=record.error_code,
            recoverable=record.recoverable,
            retryable=record.retryable,
            message=record.user_message,
            request_id=record.request_id,
            trace_id=record.trace_id,
            run_id=record.run_id,
            source_id=record.source_id,
        )
    )


def register_error_handlers(
    app: FastAPI,
    *,
    service_name: str,
    logger: logging.Logger,
    config_hash: str,
) -> None:
    @app.exception_handler(AgentSupplyShieldError)
    async def handle_application_error(request: Request, error: AgentSupplyShieldError) -> JSONResponse:
        return _error_json_response(
            request=request,
            error=error,
            service_name=service_name,
            logger=logger,
            config_hash=config_hash,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        application_error = AgentSupplyShieldError(
            category="parse_error",
            error_code="request_validation_error",
            internal_message=str(error),
            context={"errors": error.errors()},
        )
        return _error_json_response(
            request=request,
            error=application_error,
            service_name=service_name,
            logger=logger,
            config_hash=config_hash,
        )

    @app.exception_handler(HTTPException)
    async def handle_http_exception(request: Request, error: HTTPException) -> JSONResponse:
        category: ErrorCategory = "rate_limit_error" if error.status_code == 429 else "report_error"
        defaults = ERROR_CATEGORY_DEFAULTS[category]
        application_error = AgentSupplyShieldError(
            category=category,
            error_code=f"http_{error.status_code}",
            user_message=str(error.detail or defaults["user_message"]),
            internal_message=str(error.detail or defaults["user_message"]),
            status_code=error.status_code,
            context={"headers": dict(error.headers or {})},
        )
        return _error_json_response(
            request=request,
            error=application_error,
            service_name=service_name,
            logger=logger,
            config_hash=config_hash,
        )

    @app.exception_handler(Exception)
    async def handle_unhandled_exception(request: Request, error: Exception) -> JSONResponse:
        return _error_json_response(
            request=request,
            error=error,
            service_name=service_name,
            logger=logger,
            config_hash=config_hash,
        )


def _error_json_response(
    *,
    request: Request,
    error: Exception,
    service_name: str,
    logger: logging.Logger,
    config_hash: str,
) -> JSONResponse:
    trace_context = _trace_context_for_request(request, config_hash=config_hash)
    record = build_error_record(error, trace_context=trace_context)
    _log_error_record(record, service_name=service_name, logger=logger)
    response = JSONResponse(
        status_code=record.status_code,
        content=build_error_response(record).model_dump(mode="json"),
    )
    response.headers["x-request-id"] = record.request_id
    response.headers["x-trace-id"] = record.trace_id
    response.headers["x-config-hash"] = record.config_hash
    return response


def _trace_context_for_request(request: Request, *, config_hash: str) -> TraceContext:
    trace_context = getattr(request.state, "trace_context", None)
    if isinstance(trace_context, TraceContext):
        return trace_context
    return new_request_trace_context(config_hash=config_hash)


def _log_error_record(record: ErrorRecord, *, service_name: str, logger: logging.Logger) -> None:
    trace_context = TraceContext(
        request_id=record.request_id,
        trace_id=record.trace_id,
        run_id=record.run_id,
        source_id=record.source_id,
        config_hash=record.config_hash,
    )
    event = build_structured_log_event(
        service=service_name,
        event_type=record.category,
        status="error",
        trace_context=trace_context,
        latency_ms=0,
        error_code=record.error_code,
        metadata={
            "recoverable": record.recoverable,
            "retryable": record.retryable,
            "user_message": record.user_message,
            "internal_message": record.internal_message,
            "internal_stack_trace": record.internal_stack_trace,
            "context": record.context,
        },
    )
    logger.error(structured_log_event_to_json(event))
