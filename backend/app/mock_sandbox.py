from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


SandboxComponent = Literal[
    "mock_filesystem",
    "mock_customer_database",
    "mock_email_sender",
    "mock_http_client",
    "mock_issue_tracker",
    "mock_slack_docs_connector",
    "mock_secrets_vault",
]

DEFAULT_MOCK_SECRETS: dict[str, str] = {
    "api_key": "FAKE_API_KEY_123",
    "customer_token": "MOCK_CUSTOMER_TOKEN_ABC",
    "github_token": "TEST_GITHUB_TOKEN_DO_NOT_USE",
    "db_password": "SANDBOX_DB_PASSWORD_FAKE",
}
FAKE_SECRET_MARKERS: tuple[str, ...] = ("FAKE", "MOCK", "TEST", "SANDBOX", "DO_NOT_USE")

RecordOperation = Callable[[SandboxComponent, str, dict[str, Any], Any], None]


class SandboxOperation(BaseModel):
    operation_id: str
    component: SandboxComponent
    operation: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any | None = None

    @field_validator("operation_id", "operation")
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("sandbox operation identifiers and names must not be blank.")
        return value


class MockHTTPResponse(BaseModel):
    status_code: int = Field(ge=100, le=599)
    body: dict[str, Any] = Field(default_factory=dict)


class MockFilesystem:
    def __init__(self, files: dict[str, str] | None = None, recorder: RecordOperation | None = None) -> None:
        self.files = dict(files or {})
        self._record = recorder or _noop_record

    def read_file(self, path: str) -> str:
        _require_nonblank(path, "path")
        if path not in self.files:
            raise FileNotFoundError(path)
        content = self.files[path]
        self._record("mock_filesystem", "read_file", {"path": path}, {"bytes": len(content)})
        return content

    def write_file(self, path: str, content: str) -> None:
        _require_nonblank(path, "path")
        self.files[path] = content
        self._record("mock_filesystem", "write_file", {"path": path}, {"bytes": len(content)})

    def list_files(self) -> list[str]:
        paths = sorted(self.files)
        self._record("mock_filesystem", "list_files", {}, {"count": len(paths)})
        return paths


class MockCustomerDatabase:
    def __init__(
        self,
        customers: dict[str, dict[str, Any]] | None = None,
        recorder: RecordOperation | None = None,
    ) -> None:
        self.customers = {customer_id: dict(value) for customer_id, value in (customers or {}).items()}
        self._record = recorder or _noop_record

    def get_customer(self, customer_id: str) -> dict[str, Any]:
        _require_nonblank(customer_id, "customer_id")
        customer = dict(self.customers.get(customer_id, {}))
        self._record("mock_customer_database", "get_customer", {"customer_id": customer_id}, {"found": bool(customer)})
        return customer

    def update_customer(self, customer_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        _require_nonblank(customer_id, "customer_id")
        customer = dict(self.customers.get(customer_id, {}))
        customer.update(updates)
        self.customers[customer_id] = customer
        self._record(
            "mock_customer_database",
            "update_customer",
            {"customer_id": customer_id, "fields": sorted(updates)},
            {"stored": True},
        )
        return dict(customer)


class MockEmailSender:
    def __init__(self, recorder: RecordOperation | None = None) -> None:
        self.outbox: list[dict[str, str]] = []
        self._record = recorder or _noop_record

    def send_email(self, *, to: str, subject: str, body: str) -> str:
        _require_nonblank(to, "to")
        _require_nonblank(subject, "subject")
        message_id = f"mock_email_{len(self.outbox) + 1}"
        self.outbox.append({"message_id": message_id, "to": to, "subject": subject, "body": body})
        self._record("mock_email_sender", "send_email", {"to": to, "subject": subject}, {"message_id": message_id})
        return message_id


class MockHTTPClient:
    def __init__(
        self,
        responses: dict[str, MockHTTPResponse | dict[str, Any]] | None = None,
        recorder: RecordOperation | None = None,
    ) -> None:
        self.responses = {
            url: response if isinstance(response, MockHTTPResponse) else MockHTTPResponse.model_validate(response)
            for url, response in (responses or {}).items()
        }
        self._record = recorder or _noop_record

    def register_response(self, url: str, response: MockHTTPResponse | dict[str, Any]) -> None:
        _require_nonblank(url, "url")
        self.responses[url] = response if isinstance(response, MockHTTPResponse) else MockHTTPResponse.model_validate(response)
        self._record("mock_http_client", "register_response", {"url": url}, {"registered": True})

    def get(self, url: str) -> MockHTTPResponse:
        _require_nonblank(url, "url")
        response = self.responses.get(url, MockHTTPResponse(status_code=404, body={"error": "mock response not registered"}))
        self._record("mock_http_client", "get", {"url": url}, {"status_code": response.status_code})
        return response

    def post(self, url: str, payload: dict[str, Any]) -> MockHTTPResponse:
        _require_nonblank(url, "url")
        response = self.responses.get(url, MockHTTPResponse(status_code=202, body={"accepted": True, "url": url}))
        self._record("mock_http_client", "post", {"url": url, "payload_keys": sorted(payload)}, {"status_code": response.status_code})
        return response


class MockIssueTracker:
    def __init__(self, recorder: RecordOperation | None = None) -> None:
        self.issues: dict[str, dict[str, Any]] = {}
        self._record = recorder or _noop_record

    def create_issue(self, *, title: str, body: str, labels: list[str] | None = None) -> str:
        _require_nonblank(title, "title")
        issue_id = f"mock_issue_{len(self.issues) + 1}"
        self.issues[issue_id] = {"issue_id": issue_id, "title": title, "body": body, "labels": labels or []}
        self._record("mock_issue_tracker", "create_issue", {"title": title, "labels": labels or []}, {"issue_id": issue_id})
        return issue_id

    def update_issue(self, issue_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        _require_nonblank(issue_id, "issue_id")
        if issue_id not in self.issues:
            raise KeyError(issue_id)
        self.issues[issue_id].update(updates)
        self._record("mock_issue_tracker", "update_issue", {"issue_id": issue_id, "fields": sorted(updates)}, {"updated": True})
        return dict(self.issues[issue_id])


class MockSlackDocsConnector:
    def __init__(self, docs: dict[str, str] | None = None, recorder: RecordOperation | None = None) -> None:
        self.docs = dict(docs or {})
        self.messages: list[dict[str, str]] = []
        self._record = recorder or _noop_record

    def read_doc(self, doc_id: str) -> str:
        _require_nonblank(doc_id, "doc_id")
        content = self.docs.get(doc_id, "")
        self._record("mock_slack_docs_connector", "read_doc", {"doc_id": doc_id}, {"bytes": len(content)})
        return content

    def post_message(self, *, channel: str, text: str) -> str:
        _require_nonblank(channel, "channel")
        message_id = f"mock_message_{len(self.messages) + 1}"
        self.messages.append({"message_id": message_id, "channel": channel, "text": text})
        self._record("mock_slack_docs_connector", "post_message", {"channel": channel}, {"message_id": message_id})
        return message_id


class MockSecretsVault:
    def __init__(self, secrets: dict[str, str] | None = None, recorder: RecordOperation | None = None) -> None:
        self.secrets = dict(secrets or DEFAULT_MOCK_SECRETS)
        _validate_fake_secrets(self.secrets)
        self._record = recorder or _noop_record

    def list_secret_names(self) -> list[str]:
        names = sorted(self.secrets)
        self._record("mock_secrets_vault", "list_secret_names", {}, {"count": len(names)})
        return names

    def get_secret(self, name: str) -> str:
        _require_nonblank(name, "name")
        if name not in self.secrets:
            raise KeyError(name)
        self._record("mock_secrets_vault", "get_secret", {"name": name}, {"value": "<mock-secret>"})
        return self.secrets[name]


class MockSandboxEnvironment:
    component_names: tuple[SandboxComponent, ...] = (
        "mock_filesystem",
        "mock_customer_database",
        "mock_email_sender",
        "mock_http_client",
        "mock_issue_tracker",
        "mock_slack_docs_connector",
        "mock_secrets_vault",
    )

    def __init__(self) -> None:
        self.trace: list[SandboxOperation] = []
        self.filesystem = MockFilesystem(recorder=self._record)
        self.customer_database = MockCustomerDatabase(recorder=self._record)
        self.email_sender = MockEmailSender(recorder=self._record)
        self.http_client = MockHTTPClient(recorder=self._record)
        self.issue_tracker = MockIssueTracker(recorder=self._record)
        self.slack_docs_connector = MockSlackDocsConnector(recorder=self._record)
        self.secrets_vault = MockSecretsVault(recorder=self._record)

    def reset_trace(self) -> None:
        self.trace.clear()

    def _record(self, component: SandboxComponent, operation: str, arguments: dict[str, Any], result: Any) -> None:
        self.trace.append(
            SandboxOperation(
                operation_id=f"sandbox_op_{len(self.trace) + 1}",
                component=component,
                operation=operation,
                arguments=arguments,
                result=result,
            )
        )


def create_mock_sandbox_environment() -> MockSandboxEnvironment:
    return MockSandboxEnvironment()


def _validate_fake_secrets(secrets: dict[str, str]) -> None:
    for name, value in secrets.items():
        _require_nonblank(name, "secret name")
        _require_nonblank(value, "secret value")
        upper_value = value.upper()
        if not any(marker in upper_value for marker in FAKE_SECRET_MARKERS):
            raise ValueError("mock sandbox secrets must be clearly fake.")


def _require_nonblank(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank.")


def _noop_record(component: SandboxComponent, operation: str, arguments: dict[str, Any], result: Any) -> None:
    return None
