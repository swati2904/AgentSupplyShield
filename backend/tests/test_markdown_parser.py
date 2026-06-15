from pathlib import Path

from app.markdown_parser import parse_markdown_file, parse_markdown_text


def test_markdown_parser_extracts_structured_content() -> None:
    markdown = """# Safe Weather Tool

This tool reads weather data from [Example Weather](https://example.test/weather).
Set WEATHER_API_KEY before running the scan.

## Usage

```bash
export WEATHER_API_KEY=test-value
python run.py
```
"""

    result = parse_markdown_text(markdown, path="README.md")

    assert [(heading.level, heading.text, heading.start_line) for heading in result.headings] == [
        (1, "Safe Weather Tool", 1),
        (2, "Usage", 6),
    ]
    assert [(paragraph.start_line, paragraph.end_line, paragraph.text) for paragraph in result.paragraphs] == [
        (
            3,
            4,
            "This tool reads weather data from [Example Weather](https://example.test/weather). "
            "Set WEATHER_API_KEY before running the scan.",
        )
    ]
    assert result.code_blocks[0].language == "bash"
    assert result.code_blocks[0].text == "export WEATHER_API_KEY=test-value\npython run.py"
    assert result.code_blocks[0].start_line == 8
    assert result.code_blocks[0].end_line == 11
    assert [(link.label, link.url, link.start_line) for link in result.links] == [
        ("Example Weather", "https://example.test/weather", 3)
    ]
    assert [(env_var.name, env_var.start_line) for env_var in result.env_vars] == [
        ("WEATHER_API_KEY", 4),
        ("WEATHER_API_KEY", 9),
    ]


def test_markdown_parser_handles_unclosed_code_block() -> None:
    markdown = """# Notes

```json
{"env": "SAFE_TOKEN"}
"""

    result = parse_markdown_text(markdown)

    assert len(result.code_blocks) == 1
    assert result.code_blocks[0].language == "json"
    assert result.code_blocks[0].start_line == 3
    assert result.code_blocks[0].end_line == 4
    assert result.code_blocks[0].text == '{"env": "SAFE_TOKEN"}'
    assert [(env_var.name, env_var.start_line) for env_var in result.env_vars] == [("SAFE_TOKEN", 4)]


def test_markdown_parser_reads_file_with_path(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("# Local README\n\nSee [docs](docs/usage.md).\n", encoding="utf-8")

    result = parse_markdown_file(readme)

    assert result.path == str(readme)
    assert result.headings[0].text == "Local README"
    assert result.links[0].url == "docs/usage.md"
