import json
from pathlib import Path

from app.artifact_storage import LocalArtifactStore
from app.ingestion import ingest_local_folder


def test_local_artifact_store_persists_raw_and_parsed_separately(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    raw_text = "# Tool\n\nReads public events.\n"
    (source / "README.md").write_text(raw_text, encoding="utf-8")
    artifact = ingest_local_folder(source).files[0]
    store = LocalArtifactStore(tmp_path / "store")

    stored = store.persist_artifact(
        source_id="source_local",
        artifact_id="artifact_readme",
        file_artifact=artifact,
        raw_text=raw_text,
        artifact_type="markdown",
        parser_name="markdown",
        parsed_payload={"headings": [{"text": "Tool", "start_line": 1, "end_line": 1}]},
    )

    assert Path(stored.raw_path).is_file()
    assert Path(stored.parsed_path).is_file()
    assert Path(stored.raw_path).parent.name == "raw_artifacts"
    assert Path(stored.parsed_path).parent.name == "parsed_artifacts"
    assert Path(stored.raw_path).read_text(encoding="utf-8") == raw_text

    parsed_record = json.loads(Path(stored.parsed_path).read_text(encoding="utf-8"))
    assert parsed_record["artifact_id"] == "artifact_readme"
    assert parsed_record["source_id"] == "source_local"
    assert parsed_record["relative_path"] == "README.md"
    assert parsed_record["artifact_type"] == "markdown"
    assert parsed_record["parsed_payload"]["headings"][0]["text"] == "Tool"
    assert "raw_text" not in parsed_record


def test_local_scan_writes_artifact_store_outputs(tmp_path: Path) -> None:
    from app.local_scan import scan_local_folder

    source = tmp_path / "scan_source"
    reports = tmp_path / "reports"
    store = tmp_path / "artifact_store"
    source.mkdir()
    (source / "README.md").write_text("# Tool\n\nReads public events.\n", encoding="utf-8")

    result = scan_local_folder(source, output_dir=reports, artifact_store_dir=store)

    assert result.artifact_storage_path == str(store.resolve())
    assert len(result.stored_artifacts) == 1
    stored = result.stored_artifacts[0]
    assert Path(stored.raw_path).is_file()
    assert Path(stored.parsed_path).is_file()
    parsed_record = json.loads(Path(stored.parsed_path).read_text(encoding="utf-8"))
    assert parsed_record["artifact_id"] == stored.artifact_id
    assert parsed_record["parsed_payload"]["headings"][0]["text"] == "Tool"
