import logging
from time import perf_counter

from fastapi import FastAPI
from fastapi import Request

from app.config import config_hash, load_project_config
from app.error_handling import register_error_handlers
from app.observability import build_structured_log_event, new_request_trace_context, structured_log_event_to_json


project_config = load_project_config()
project_config_hash = config_hash(project_config)
logger = logging.getLogger("agentsupplyshield.api")
app = FastAPI(title="AgentSupplyShield API", debug=project_config.app.debug)
register_error_handlers(
    app,
    service_name=project_config.app.service_name,
    logger=logger,
    config_hash=project_config_hash,
)


@app.middleware("http")
async def trace_and_log_request(request: Request, call_next):
    trace_context = new_request_trace_context(
        request_id=request.headers.get("x-request-id"),
        trace_id=request.headers.get("x-trace-id"),
        config_hash=project_config_hash,
    )
    request.state.trace_context = trace_context
    start = perf_counter()
    response = None
    status = "ok"
    error_code = None

    try:
        response = await call_next(request)
        if response.status_code >= 400:
            status = "error"
            error_code = f"http_{response.status_code}"
        return response
    except Exception:
        status = "error"
        error_code = "unhandled_exception"
        raise
    finally:
        latency_ms = (perf_counter() - start) * 1000
        if response is not None:
            response.headers["x-request-id"] = trace_context.request_id
            response.headers["x-trace-id"] = trace_context.trace_id
            response.headers["x-config-hash"] = trace_context.config_hash
        event = build_structured_log_event(
            service=project_config.app.service_name,
            event_type="http_request",
            status=status,
            trace_context=trace_context,
            latency_ms=latency_ms,
            error_code=error_code,
            metadata={"method": request.method, "path": request.url.path},
        )
        logger.info(structured_log_event_to_json(event))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": project_config.app.service_name}
