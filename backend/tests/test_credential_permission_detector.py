from app.credential_permission_detector import detect_credential_and_permission_signals


def test_detector_finds_credential_references_without_real_secret_values() -> None:
    text = """# Demo credential references
Set DEMO_API_KEY before running the sample.
Use DEMO_TOKEN for the synthetic fixture.
Configure DEMO_SECRET for local testing.
The docs mention DEMO_PASSWORD as a fake variable name.
Never paste a DEMO_PRIVATE_KEY value into docs.
"""

    findings = detect_credential_and_permission_signals(text, artifact_id="artifact_credentials")

    categories = {finding.category for finding in findings}
    assert categories == {"API_KEY", "TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY"}
    assert {finding.family for finding in findings} == {"credential_reference"}
    assert all(finding.evidence_span.artifact_id == "artifact_credentials" for finding in findings)
    assert all(finding.rationale for finding in findings)
    assert all(finding.recommendation for finding in findings)
    assert all(0.0 <= finding.confidence <= 1.0 for finding in findings)

    by_category = {finding.category: finding for finding in findings}
    assert by_category["PRIVATE_KEY"].severity == "critical"
    assert by_category["API_KEY"].evidence_span.start_line == 2


def test_detector_finds_permission_indicators() -> None:
    text = """# Permission notes
This tool can read local files from an approved directory.
It makes HTTP requests to external endpoints.
It can run shell commands for maintenance.
The connector can query database records.
The service may send email through SMTP.
It can read credentials from a mock vault.
Setup may run npm install for dependencies.
Advanced mode can execute code snippets.
"""

    findings = detect_credential_and_permission_signals(text, artifact_id="artifact_permissions")

    categories = {finding.category for finding in findings}
    assert categories == {
        "filesystem_access",
        "network_access",
        "shell_execution",
        "database_access",
        "email_send",
        "credential_access",
        "package_install",
        "code_execution",
    }
    assert {finding.family for finding in findings} == {"permission_signal"}
    assert all(finding.evidence_span.artifact_id == "artifact_permissions" for finding in findings)
    assert all(finding.evidence_span.start_line == finding.evidence_span.end_line for finding in findings)

    by_category = {finding.category: finding for finding in findings}
    assert by_category["shell_execution"].severity == "high"
    assert by_category["code_execution"].evidence_span.start_line == 9


def test_detector_returns_no_findings_for_clean_purpose_text() -> None:
    text = """# Calendar Reader

Reads public calendar event titles and returns a short summary.
This fixture intentionally avoids credential names and risky capabilities.
"""

    findings = detect_credential_and_permission_signals(text, artifact_id="artifact_clean")

    assert findings == []


def test_detector_ids_are_stable() -> None:
    text = "Set DEMO_API_KEY before using the synthetic fixture."

    first = detect_credential_and_permission_signals(text, artifact_id="artifact_stable")
    second = detect_credential_and_permission_signals(text, artifact_id="artifact_stable")

    assert len(first) == 1
    assert first[0].finding_id == second[0].finding_id
    assert first[0].evidence_span.span_id == second[0].evidence_span.span_id
    assert first[0].evidence_span.content_hash == second[0].evidence_span.content_hash
