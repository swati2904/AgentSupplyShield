import json
import logging
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import config_hash, load_project_config
from app.local_scan import scan_local_folder
from app.main import app
from app.observability import (
    build_structured_log_event,
    new_request_trace_context,
    new_scan_trace_context,
    structured_log_event_to_json,
)


CONFIG_HASH = config_hash(load_project_config())


def test_request_trace_context_and_structured_log_fields() -> None:
    trace_context = new_request_trace_context(
        request_id="req_test",
        trace_id="trace_test",
        config_hash=CONFIG_HASH,
    )
    event = build_structured_log_event(
        service="agentsupplyshield-api",
        event_type="http_request",
        status="ok",
        trace_context=trace_context,
        latency_ms=12.3456,
        metadata={"method": "GET", "path": "/health"},
    )
    payload = json.loads(structured_log_event_to_json(event))

    assert payload["timestamp"].endswith("Z")
    assert payload["service"] == "agentsupplyshield-api"
    assert payload["request_id"] == "req_test"
    assert payload["trace_id"] == "trace_test"
    assert payload["config_hash"] == CONFIG_HASH
    assert payload["run_id"] is None
    assert payload["source_id"] is None
    assert payload["tool_id"] is None
    assert payload["event_type"] == "http_request"
    assert payload["status"] == "ok"
    assert payload["latency_ms"] == 12.346
    assert payload["error_code"] is None
    assert payload["metadata"] == {"method": "GET", "path": "/health"}


def test_scan_trace_context_contains_phase_14_3_fields() -> None:
    trace_context = new_scan_trace_context(
        run_id="run_scan_1",
        source_id="source_repo_1",
        config_hash=CONFIG_HASH,
    )

    assert trace_context.run_id == "run_scan_1"
    assert trace_context.source_id == "source_repo_1"
    assert trace_context.request_id.startswith("req_")
    assert trace_context.trace_id.startswith("trace_")
    assert trace_context.config_hash == CONFIG_HASH


def test_health_endpoint_returns_trace_headers_and_structured_log(caplog) -> None:
    client = TestClient(app)

    with caplog.at_level(logging.INFO, logger="agentsupplyshield.api"):
        response = client.get(
            "/health",
            headers={"x-request-id": "req_header", "x-trace-id": "trace_header"},
        )

    log_payloads = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "agentsupplyshield.api" and record.message.startswith("{")
    ]

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "req_header"
    assert response.headers["x-trace-id"] == "trace_header"
    assert response.headers["x-config-hash"] == CONFIG_HASH
    assert log_payloads[-1]["service"] == "agentsupplyshield-api"
    assert log_payloads[-1]["request_id"] == "req_header"
    assert log_payloads[-1]["trace_id"] == "trace_header"
    assert log_payloads[-1]["config_hash"] == CONFIG_HASH
    assert log_payloads[-1]["event_type"] == "http_request"
    assert log_payloads[-1]["status"] == "ok"
    assert log_payloads[-1]["metadata"] == {"method": "GET", "path": "/health"}


def test_local_scan_result_includes_trace_context(tmp_path: Path) -> None:
    source = tmp_path / "source"
    output = tmp_path / "reports"
    source.mkdir()
    (source / "README.md").write_text("# Safe Tool\n\nSummarizes local notes.\n", encoding="utf-8")

    result = scan_local_folder(source, output_dir=output)

    assert result.trace_context.run_id == result.run_id
    assert result.trace_context.source_id == result.source_id
    assert result.trace_context.request_id.startswith("req_")
    assert result.trace_context.trace_id.startswith("trace_")
    assert result.trace_context.config_hash == CONFIG_HASH
