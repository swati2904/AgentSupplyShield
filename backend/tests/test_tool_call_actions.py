from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.tool_call_actions import TOOL_CALL_ACTION_FIELDS, ToolCallAction


def test_tool_call_action_fields_match_roadmap_schema() -> None:
    assert TOOL_CALL_ACTION_FIELDS == (
        "action_type",
        "tool_name",
        "arguments",
        "risk_level",
        "source_context_ids",
        "timestamp",
    )
    assert tuple(ToolCallAction.model_fields) == TOOL_CALL_ACTION_FIELDS


def test_tool_call_action_accepts_structured_agent_action() -> None:
    timestamp = datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc)

    action = ToolCallAction(
        action_type="read_file",
        tool_name="mock_filesystem",
        arguments={"path": "README.md"},
        risk_level="low",
        source_context_ids=["span_1", "artifact_1"],
        timestamp=timestamp,
    )

    assert action.action_type == "read_file"
    assert action.tool_name == "mock_filesystem"
    assert action.arguments == {"path": "README.md"}
    assert action.risk_level == "low"
    assert action.source_context_ids == ["span_1", "artifact_1"]
    assert action.timestamp == timestamp


def test_tool_call_action_defaults_are_isolated_and_timestamped() -> None:
    first = ToolCallAction(action_type="list_files", tool_name="mock_filesystem", risk_level="low")
    second = ToolCallAction(action_type="list_files", tool_name="mock_filesystem", risk_level="low")

    first.arguments["path"] = "README.md"
    first.source_context_ids.append("span_1")

    assert second.arguments == {}
    assert second.source_context_ids == []
    assert first.timestamp.tzinfo is not None
    assert second.timestamp.tzinfo is not None


def test_tool_call_action_serializes_timestamp_for_trace_artifacts() -> None:
    action = ToolCallAction(
        action_type="send_email",
        tool_name="mock_email_sender",
        arguments={"to": "reviewer@example.test"},
        risk_level="high",
        source_context_ids=["span_email"],
        timestamp=datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc),
    )

    payload = action.model_dump(mode="json")

    assert payload == {
        "action_type": "send_email",
        "tool_name": "mock_email_sender",
        "arguments": {"to": "reviewer@example.test"},
        "risk_level": "high",
        "source_context_ids": ["span_email"],
        "timestamp": "2026-06-17T12:00:00Z",
    }


def test_tool_call_action_rejects_blank_strings_and_invalid_risk_level() -> None:
    with pytest.raises(ValidationError):
        ToolCallAction(action_type=" ", tool_name="mock_filesystem", risk_level="low")

    with pytest.raises(ValidationError):
        ToolCallAction(action_type="read_file", tool_name=" ", risk_level="low")

    with pytest.raises(ValidationError):
        ToolCallAction(
            action_type="read_file",
            tool_name="mock_filesystem",
            risk_level="low",
            source_context_ids=["span_1", " "],
        )

    with pytest.raises(ValidationError):
        ToolCallAction(action_type="read_file", tool_name="mock_filesystem", risk_level="severe")
