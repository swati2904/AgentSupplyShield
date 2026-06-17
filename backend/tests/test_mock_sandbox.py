import pytest

from app.mock_sandbox import (
    DEFAULT_MOCK_SECRETS,
    MockHTTPResponse,
    MockSecretsVault,
    create_mock_sandbox_environment,
)


def test_mock_sandbox_environment_exposes_roadmap_components_and_fake_secrets() -> None:
    sandbox = create_mock_sandbox_environment()

    assert sandbox.component_names == (
        "mock_filesystem",
        "mock_customer_database",
        "mock_email_sender",
        "mock_http_client",
        "mock_issue_tracker",
        "mock_slack_docs_connector",
        "mock_secrets_vault",
    )
    assert sandbox.secrets_vault.list_secret_names() == sorted(DEFAULT_MOCK_SECRETS)
    assert sandbox.secrets_vault.get_secret("api_key") == "FAKE_API_KEY_123"
    assert sandbox.trace[-1].result == {"value": "<mock-secret>"}


def test_mock_filesystem_is_in_memory_and_does_not_touch_real_files(tmp_path) -> None:
    sandbox = create_mock_sandbox_environment()
    real_path = tmp_path / "should_not_exist.txt"

    sandbox.filesystem.write_file(str(real_path), "sandbox-only content")

    assert sandbox.filesystem.read_file(str(real_path)) == "sandbox-only content"
    assert not real_path.exists()
    assert sandbox.trace[0].component == "mock_filesystem"
    assert sandbox.trace[0].operation == "write_file"


def test_mock_http_client_uses_registered_responses_without_network() -> None:
    sandbox = create_mock_sandbox_environment()
    sandbox.http_client.register_response(
        "https://api.example.test/status",
        MockHTTPResponse(status_code=200, body={"ok": True}),
    )

    registered = sandbox.http_client.get("https://api.example.test/status")
    unregistered = sandbox.http_client.get("https://unregistered.example.test")
    posted = sandbox.http_client.post("https://api.example.test/events", {"event": "sandbox"})

    assert registered.status_code == 200
    assert registered.body == {"ok": True}
    assert unregistered.status_code == 404
    assert posted.status_code == 202
    assert [event.operation for event in sandbox.trace] == ["register_response", "get", "get", "post"]


def test_mock_email_issue_tracker_database_and_docs_connector_record_only_mock_state() -> None:
    sandbox = create_mock_sandbox_environment()

    customer = sandbox.customer_database.update_customer("cust_1", {"tier": "test"})
    message_id = sandbox.email_sender.send_email(
        to="reviewer@example.test",
        subject="Sandbox notification",
        body="This is a mock message.",
    )
    issue_id = sandbox.issue_tracker.create_issue(title="Sandbox review", body="Mock issue", labels=["sandbox"])
    sandbox.slack_docs_connector.docs["runbook"] = "Mock runbook content"
    doc_text = sandbox.slack_docs_connector.read_doc("runbook")
    slack_message_id = sandbox.slack_docs_connector.post_message(channel="sandbox-alerts", text="Mock alert")

    assert customer == {"tier": "test"}
    assert sandbox.email_sender.outbox[0]["message_id"] == message_id
    assert sandbox.issue_tracker.issues[issue_id]["title"] == "Sandbox review"
    assert doc_text == "Mock runbook content"
    assert sandbox.slack_docs_connector.messages[0]["message_id"] == slack_message_id
    assert [event.component for event in sandbox.trace] == [
        "mock_customer_database",
        "mock_email_sender",
        "mock_issue_tracker",
        "mock_slack_docs_connector",
        "mock_slack_docs_connector",
    ]


def test_mock_secrets_vault_rejects_values_that_are_not_clearly_fake() -> None:
    with pytest.raises(ValueError, match="clearly fake"):
        MockSecretsVault({"api_key": "sk-live-secret"})


def test_mock_sandbox_validates_blank_inputs_and_can_reset_trace() -> None:
    sandbox = create_mock_sandbox_environment()

    with pytest.raises(ValueError, match="path"):
        sandbox.filesystem.write_file(" ", "content")

    sandbox.filesystem.write_file("README.md", "content")
    assert sandbox.trace

    sandbox.reset_trace()

    assert sandbox.trace == []
