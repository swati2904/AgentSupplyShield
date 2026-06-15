from pathlib import Path

from app.schema_parser import parse_tool_schema_file, parse_tool_schema_text


def test_parse_json_tool_schema_extracts_tool_metadata() -> None:
    schema = """
{
  "name": "weather_lookup",
  "description": "Fetches weather from https://api.example.test/weather.",
  "parameters": {
    "type": "object",
    "properties": {
      "city": {
        "type": "string",
        "description": "City to look up."
      },
      "units": {
        "type": "string",
        "description": "Unit system."
      }
    },
    "required": ["city"]
  },
  "examples": [{"city": "Seattle"}]
}
"""

    result = parse_tool_schema_text(schema, schema_format="json", path="tool.json")

    assert result.parse_error is None
    assert result.urls == ["https://api.example.test/weather"]
    assert len(result.tools) == 1
    tool = result.tools[0]
    assert tool.name == "weather_lookup"
    assert tool.description == "Fetches weather from https://api.example.test/weather."
    assert tool.required_fields == ["city"]
    assert [(parameter.name, parameter.description, parameter.required) for parameter in tool.parameters] == [
        ("city", "City to look up.", True),
        ("units", "Unit system.", False),
    ]
    assert tool.examples == [{"city": "Seattle"}]
    assert tool.urls == ["https://api.example.test/weather"]


def test_parse_yaml_tool_schema_extracts_list_of_tools() -> None:
    schema = """
tools:
  - name: docs_search
    description: Search local docs and return matching snippets.
    input_schema:
      type: object
      properties:
        query:
          type: string
          description: Search query.
      required:
        - query
    examples:
      - query: release notes
    endpoint: https://docs.example.test/search
"""

    result = parse_tool_schema_text(schema, schema_format="yaml", path="tools.yaml")

    assert result.parse_error is None
    assert result.urls == ["https://docs.example.test/search"]
    assert len(result.tools) == 1
    tool = result.tools[0]
    assert tool.name == "docs_search"
    assert tool.required_fields == ["query"]
    assert [(parameter.name, parameter.description, parameter.required) for parameter in tool.parameters] == [
        ("query", "Search query.", True)
    ]
    assert tool.examples == [{"query": "release notes"}]


def test_parse_malformed_json_returns_safe_error() -> None:
    result = parse_tool_schema_text('{"name": "broken"', schema_format="json")

    assert result.tools == []
    assert result.urls == []
    assert result.parse_error is not None
    assert "Invalid JSON schema" in result.parse_error


def test_parse_malformed_yaml_returns_safe_error() -> None:
    result = parse_tool_schema_text("tools:\n  - name: bad\n    required: [unterminated\n", schema_format="yaml")

    assert result.tools == []
    assert result.urls == []
    assert result.parse_error is not None
    assert "Invalid YAML schema" in result.parse_error


def test_parse_tool_schema_file_detects_format_from_extension(tmp_path: Path) -> None:
    schema_path = tmp_path / "tool.json"
    schema_path.write_text('{"name": "reader", "description": "Read docs."}', encoding="utf-8")

    result = parse_tool_schema_file(schema_path)

    assert result.path == str(schema_path)
    assert result.schema_format == "json"
    assert result.tools[0].name == "reader"
