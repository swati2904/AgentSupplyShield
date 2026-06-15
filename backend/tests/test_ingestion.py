from pathlib import Path

import pytest

from app.ingestion import ingest_local_folder


def test_ingestion_includes_allowed_local_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Safe tool\n", encoding="utf-8")
    (tmp_path / "tool.json").write_text('{"name": "safe_tool"}\n', encoding="utf-8")
    (tmp_path / "config.yaml").write_text("name: safe_tool\n", encoding="utf-8")
    (tmp_path / "run.exe").write_text("do not include", encoding="utf-8")

    result = ingest_local_folder(tmp_path)

    assert [file.relative_path for file in result.files] == [
        "README.md",
        "config.yaml",
        "tool.json",
    ]
    assert {file.extension for file in result.files} == {".md", ".json", ".yaml"}
    assert any(skip.relative_path == "run.exe" for skip in result.skipped)


def test_ingestion_skips_ignored_directories(tmp_path: Path) -> None:
    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "package.json").write_text('{"ignored": true}\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("# Include me\n", encoding="utf-8")

    result = ingest_local_folder(tmp_path)

    assert [file.relative_path for file in result.files] == ["README.md"]
    assert any(skip.relative_path == "node_modules" and skip.reason == "ignored_path" for skip in result.skipped)


def test_ingestion_enforces_file_size_limit(tmp_path: Path) -> None:
    (tmp_path / "small.md").write_text("small\n", encoding="utf-8")
    (tmp_path / "large.md").write_text("x" * 20, encoding="utf-8")

    result = ingest_local_folder(tmp_path, max_file_size_bytes=10)

    assert [file.relative_path for file in result.files] == ["small.md"]
    assert any(skip.relative_path == "large.md" and skip.reason == "file_too_large" for skip in result.skipped)


def test_ingestion_rejects_non_local_sources() -> None:
    with pytest.raises(ValueError, match="Only local folder paths"):
        ingest_local_folder("https://example.com/repo")
