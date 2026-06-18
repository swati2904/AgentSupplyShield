import json
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.config import config_hash, load_project_config
from app.error_handling import (
    ERROR_CATEGORIES,
    ERROR_CATEGORY_DEFAULTS,
    AgentSupplyShieldError,
    build_error_record,
    build_error_response,
    register_error_handlers,
)
from app.observability import new_request_trace_context


CONFIG_HASH = config_hash(load_project_config())


def test_error_categories_match_phase_14_4_defaults() -> None:
    assert ERROR_CATEGORIES == (
        "crawl_error",
        "parse_error",
        "embedding_error",
        "policy_error",
        "sandbox_error",
        "report_error",
        "rate_limit_error",
    )
    assert set(ERROR_CATEGORY_DEFAULTS) == set(ERROR_CATEGORIES)
    assert ERROR_CATEGORY_DEFAULTS["crawl_error"]["recoverable"] is True
    assert ERROR_CATEGORY_DEFAULTS["crawl_error"]["retryable"] is True
    assert ERROR_CATEGORY_DEFAULTS["parse_error"]["status_code"] == 422
    assert ERROR_CATEGORY_DEFAULTS["rate_limit_error"]["status_code"] == 429


def test_error_record_keeps_internal_stack_trace_out_of_user_response() -> None:
    trace_context = new_request_trace_context(
        request_id="req_error",
        trace_id="trace_error",
        config_hash=CONFIG_HASH,
    )

    try:
        raise AgentSupplyShieldError(
            category="policy_error",
            error_code="policy_missing_rule",
            user_message="Policy could not be evaluated.",
            internal_message="Policy P9 referenced a missing condition.",
            context={"policy_id": "P9"},
        )
    except AgentSupplyShieldError as error:
        record = build_error_record(error, trace_context=trace_context)

    response = build_error_response(record).model_dump(mode="json")

    assert record.category == "policy_error"
    assert record.error_code == "policy_missing_rule"
    assert record.recoverable is False
    assert record.retryable is False
    assert record.context == {"policy_id": "P9"}
    assert any("Policy P9 referenced a missing condition." in line for line in record.internal_stack_trace)
    assert response == {
        "error": {
            "category": "policy_error",
            "error_code": "policy_missing_rule",
            "recoverable": False,
            "retryable": False,
            "message": "Policy could not be evaluated.",
            "request_id": "req_error",
            "trace_id": "trace_error",
            "run_id": None,
            "source_id": None,
        }
    }


def test_registered_error_handler_returns_safe_json_and_logs_internal_details(caplog) -> None:
    app = _test_app()
    client = TestClient(app)

    with caplog.at_level(logging.ERROR, logger="agentsupplyshield.test"):
        response = client.get("/policy-error", headers={"x-request-id": "req_handler", "x-trace-id": "trace_handler"})

    log_payloads = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "agentsupplyshield.test" and record.message.startswith("{")
    ]

    assert response.status_code == 500
    assert response.headers["x-request-id"] == "req_handler"
    assert response.headers["x-trace-id"] == "trace_handler"
    assert response.headers["x-config-hash"] == CONFIG_HASH
    assert response.json()["error"] == {
        "category": "policy_error",
        "error_code": "policy_eval_failed",
        "recoverable": False,
        "retryable": False,
        "message": "Policy decision failed.",
        "request_id": "req_handler",
        "trace_id": "trace_handler",
        "run_id": None,
        "source_id": None,
    }
    assert log_payloads[-1]["event_type"] == "policy_error"
    assert log_payloads[-1]["error_code"] == "policy_eval_failed"
    assert log_payloads[-1]["metadata"]["internal_message"] == "Missing policy condition for shell_execution."
    assert "internal_stack_trace" in log_payloads[-1]["metadata"]


def test_validation_and_rate_limit_errors_use_expected_categories() -> None:
    app = _test_app()
    client = TestClient(app)

    validation_response = client.get("/needs-int/not-an-int")
    rate_limit_response = client.get("/rate-limit")

    assert validation_response.status_code == 422
    assert validation_response.json()["error"]["category"] == "parse_error"
    assert validation_response.json()["error"]["error_code"] == "request_validation_error"
    assert validation_response.json()["error"]["recoverable"] is True
    assert validation_response.json()["error"]["retryable"] is False
    assert rate_limit_response.status_code == 429
    assert rate_limit_response.json()["error"]["category"] == "rate_limit_error"
    assert rate_limit_response.json()["error"]["error_code"] == "http_429"
    assert rate_limit_response.json()["error"]["recoverable"] is True
    assert rate_limit_response.json()["error"]["retryable"] is True


def test_unhandled_errors_are_normalized_to_report_error() -> None:
    app = _test_app()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/unhandled")

    assert response.status_code == 500
    assert response.json()["error"]["category"] == "report_error"
    assert response.json()["error"]["error_code"] == "unhandled_exception"
    assert response.json()["error"]["message"] == ERROR_CATEGORY_DEFAULTS["report_error"]["user_message"]


def _test_app() -> FastAPI:
    app = FastAPI()
    logger = logging.getLogger("agentsupplyshield.test")

    @app.middleware("http")
    async def trace_context_middleware(request: Request, call_next):
        request.state.trace_context = new_request_trace_context(
            request_id=request.headers.get("x-request-id"),
            trace_id=request.headers.get("x-trace-id"),
            config_hash=CONFIG_HASH,
        )
        return await call_next(request)

    register_error_handlers(
        app,
        service_name="agentsupplyshield-api",
        logger=logger,
        config_hash=CONFIG_HASH,
    )

    @app.get("/policy-error")
    def policy_error() -> None:
        raise AgentSupplyShieldError(
            category="policy_error",
            error_code="policy_eval_failed",
            user_message="Policy decision failed.",
            internal_message="Missing policy condition for shell_execution.",
        )

    @app.get("/needs-int/{value}")
    def needs_int(value: int) -> dict[str, int]:
        return {"value": value}

    @app.get("/rate-limit")
    def rate_limit() -> None:
        raise HTTPException(status_code=429, detail="Too many scan requests.")

    @app.get("/unhandled")
    def unhandled() -> None:
        raise RuntimeError("Unexpected report renderer failure.")

    return app
