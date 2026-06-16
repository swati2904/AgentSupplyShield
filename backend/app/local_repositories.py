from pathlib import Path
import json
import re

from app.models import EvidenceSpan, Finding, ScanRun


SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")


class JsonEvidenceSpanRepository:
    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path).expanduser().resolve()
        self.root_path.mkdir(parents=True, exist_ok=True)

    def upsert_evidence_span(self, evidence_span: EvidenceSpan) -> EvidenceSpan:
        self.path_for_span(evidence_span.span_id).write_text(
            _json_dump(evidence_span.model_dump(mode="json")),
            encoding="utf-8",
        )
        return evidence_span

    def get_evidence_span(self, span_id: str) -> EvidenceSpan | None:
        path = self.path_for_span(span_id)
        if not path.is_file():
            return None
        return EvidenceSpan.model_validate_json(path.read_text(encoding="utf-8"))

    def list_evidence_spans_for_artifact(self, artifact_id: str) -> list[EvidenceSpan]:
        evidence_spans = []
        for path in sorted(self.root_path.glob("*.json")):
            evidence_span = EvidenceSpan.model_validate_json(path.read_text(encoding="utf-8"))
            if evidence_span.artifact_id == artifact_id:
                evidence_spans.append(evidence_span)
        return evidence_spans

    def path_for_span(self, span_id: str) -> Path:
        return self.root_path / f"{_safe_name(span_id)}.json"


class JsonFindingRepository:
    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path).expanduser().resolve()
        self.records_dir = self.root_path / "records"
        self.run_index_dir = self.root_path / "run_index"
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self.run_index_dir.mkdir(parents=True, exist_ok=True)

    def upsert_finding(self, finding: Finding) -> Finding:
        self.path_for_finding(finding.finding_id).write_text(
            _json_dump(finding.model_dump(mode="json")),
            encoding="utf-8",
        )
        return finding

    def index_finding_for_run(self, run_id: str, finding_id: str) -> None:
        path = self.path_for_run_index(run_id)
        finding_ids = _load_string_list(path)
        if finding_id not in finding_ids:
            finding_ids.append(finding_id)
        path.write_text(_json_dump({"run_id": run_id, "finding_ids": finding_ids}), encoding="utf-8")

    def get_finding(self, finding_id: str) -> Finding | None:
        path = self.path_for_finding(finding_id)
        if not path.is_file():
            return None
        return Finding.model_validate_json(path.read_text(encoding="utf-8"))

    def list_findings_for_source(self, source_id: str) -> list[Finding]:
        findings = []
        for path in sorted(self.records_dir.glob("*.json")):
            finding = Finding.model_validate_json(path.read_text(encoding="utf-8"))
            if finding.source_id == source_id:
                findings.append(finding)
        return findings

    def list_findings_for_run(self, run_id: str) -> list[Finding]:
        findings = []
        for finding_id in _load_string_list(self.path_for_run_index(run_id)):
            finding = self.get_finding(finding_id)
            if finding is not None:
                findings.append(finding)
        return findings

    def path_for_finding(self, finding_id: str) -> Path:
        return self.records_dir / f"{_safe_name(finding_id)}.json"

    def path_for_run_index(self, run_id: str) -> Path:
        return self.run_index_dir / f"{_safe_name(run_id)}.json"


class JsonScanRunRepository:
    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path).expanduser().resolve()
        self.root_path.mkdir(parents=True, exist_ok=True)

    def upsert_scan_run(self, scan_run: ScanRun) -> ScanRun:
        self.path_for_run(scan_run.run_id).write_text(
            _json_dump(scan_run.model_dump(mode="json")),
            encoding="utf-8",
        )
        return scan_run

    def get_scan_run(self, run_id: str) -> ScanRun | None:
        path = self.path_for_run(run_id)
        if not path.is_file():
            return None
        return ScanRun.model_validate_json(path.read_text(encoding="utf-8"))

    def list_scan_runs_for_source(self, source_id: str) -> list[ScanRun]:
        scan_runs = []
        for path in sorted(self.root_path.glob("*.json")):
            scan_run = ScanRun.model_validate_json(path.read_text(encoding="utf-8"))
            if scan_run.source_id == source_id:
                scan_runs.append(scan_run)
        return scan_runs

    def path_for_run(self, run_id: str) -> Path:
        return self.root_path / f"{_safe_name(run_id)}.json"


def _safe_name(value: str) -> str:
    safe = SAFE_NAME_PATTERN.sub("_", value).strip("._")
    if not safe:
        raise ValueError("Identifier cannot be empty.")
    return safe


def _load_string_list(path: Path) -> list[str]:
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    value = payload.get("finding_ids", [])
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _json_dump(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)
