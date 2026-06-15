from pathlib import Path
from typing import Any, Literal
import json
import re

from pydantic import BaseModel, Field


SchemaFormat = Literal["json", "yaml"]
URL_PATTERN = re.compile(r"https?://[^\s\"'<>),\]]+")


class ToolParameterDefinition(BaseModel):
    name: str
    description: str | None = None
    required: bool = False
    raw_schema: dict[str, Any] = Field(default_factory=dict)


class ParsedToolDefinition(BaseModel):
    name: str
    description: str | None = None
    parameters: list[ToolParameterDefinition] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    examples: list[Any] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class ParsedToolSchemaArtifact(BaseModel):
    path: str | None = None
    schema_format: SchemaFormat
    tools: list[ParsedToolDefinition] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    parse_error: str | None = None


def parse_tool_schema_text(
    text: str,
    *,
    schema_format: SchemaFormat,
    path: str | None = None,
) -> ParsedToolSchemaArtifact:
    artifact = ParsedToolSchemaArtifact(path=path, schema_format=schema_format)
    try:
        data = _load_schema_text(text, schema_format)
    except ValueError as error:
        artifact.parse_error = str(error)
        return artifact

    artifact.urls = sorted(_extract_urls(data))
    artifact.tools = [_parse_tool(candidate) for candidate in _candidate_tool_dicts(data)]
    return artifact


def parse_tool_schema_file(path: str | Path) -> ParsedToolSchemaArtifact:
    schema_path = Path(path)
    extension = schema_path.suffix.lower()
    if extension == ".json":
        schema_format: SchemaFormat = "json"
    elif extension in {".yaml", ".yml"}:
        schema_format = "yaml"
    else:
        raise ValueError(f"Unsupported tool schema extension: {extension}")

    return parse_tool_schema_text(
        schema_path.read_text(encoding="utf-8"),
        schema_format=schema_format,
        path=str(schema_path),
    )


def _load_schema_text(text: str, schema_format: SchemaFormat) -> Any:
    if schema_format == "json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid JSON schema: {error.msg}") from error

    try:
        import yaml
    except ImportError as error:
        raise ValueError("PyYAML is required to parse YAML tool schemas.") from error

    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid YAML schema: {error}") from error


def _candidate_tool_dicts(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if not isinstance(data, dict):
        return []

    function_value = data.get("function")
    if isinstance(function_value, dict) and _has_tool_identity(function_value):
        return [function_value]

    candidates: list[dict[str, Any]] = []
    for key in ("tools", "functions"):
        value = data.get(key)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))

    tool_value = data.get("tool")
    if isinstance(tool_value, dict):
        candidates.append(tool_value)

    if _has_tool_identity(data):
        candidates.append(data)

    return candidates


def _parse_tool(data: dict[str, Any]) -> ParsedToolDefinition:
    required_fields = _extract_required_fields(data)
    return ParsedToolDefinition(
        name=str(data.get("name") or data.get("tool_name") or "unknown_tool"),
        description=_optional_string(data.get("description")),
        parameters=_extract_parameters(data, required_fields),
        required_fields=required_fields,
        examples=_extract_examples(data),
        urls=sorted(_extract_urls(data)),
    )


def _extract_parameters(data: dict[str, Any], required_fields: list[str]) -> list[ToolParameterDefinition]:
    schema = _first_dict(data, "parameters", "input_schema", "inputSchema", "schema")
    properties = schema.get("properties") if schema else None

    if isinstance(properties, dict):
        return [
            ToolParameterDefinition(
                name=str(name),
                description=_optional_string(value.get("description")) if isinstance(value, dict) else None,
                required=str(name) in required_fields,
                raw_schema=value if isinstance(value, dict) else {},
            )
            for name, value in properties.items()
        ]

    if isinstance(schema, dict):
        return [
            ToolParameterDefinition(
                name=str(name),
                description=_optional_string(value.get("description")) if isinstance(value, dict) else None,
                required=str(name) in required_fields,
                raw_schema=value if isinstance(value, dict) else {"value": value},
            )
            for name, value in schema.items()
            if name not in {"type", "required", "description", "title", "examples", "example"}
        ]

    return []


def _extract_required_fields(data: dict[str, Any]) -> list[str]:
    schema = _first_dict(data, "parameters", "input_schema", "inputSchema", "schema")
    required = schema.get("required") if schema else data.get("required")
    if not isinstance(required, list):
        return []
    return [str(field) for field in required]


def _extract_examples(data: dict[str, Any]) -> list[Any]:
    if "examples" in data:
        examples = data["examples"]
        return examples if isinstance(examples, list) else [examples]
    if "example" in data:
        return [data["example"]]
    return []


def _extract_urls(data: Any) -> set[str]:
    urls: set[str] = set()
    if isinstance(data, str):
        urls.update(_clean_url(url) for url in URL_PATTERN.findall(data))
    elif isinstance(data, dict):
        for value in data.values():
            urls.update(_extract_urls(value))
    elif isinstance(data, list):
        for item in data:
            urls.update(_extract_urls(item))
    return urls


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:")


def _first_dict(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _has_tool_identity(data: dict[str, Any]) -> bool:
    return any(key in data for key in ("name", "tool_name")) and "description" in data


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None
