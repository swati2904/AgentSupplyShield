from hashlib import sha256
from typing import Literal
import re

from pydantic import BaseModel, Field

from app.evidence import create_evidence_span
from app.models import EvidenceSpan, Severity


SignalFamily = Literal["credential_reference", "permission_signal"]
CredentialCategory = Literal["API_KEY", "TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY"]
PermissionCategory = Literal[
    "filesystem_access",
    "network_access",
    "shell_execution",
    "database_access",
    "email_send",
    "credential_access",
    "package_install",
    "code_execution",
]
SignalCategory = CredentialCategory | PermissionCategory


class SignalRule(BaseModel):
    rule_id: str
    family: SignalFamily
    category: SignalCategory
    pattern: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    recommendation: str


class SignalFinding(BaseModel):
    finding_id: str
    family: SignalFamily
    category: SignalCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str
    evidence_span: EvidenceSpan
    rationale: str
    recommendation: str


SIGNAL_RULES = [
    SignalRule(
        rule_id="cred_api_key_001",
        family="credential_reference",
        category="API_KEY",
        pattern=r"\b([A-Z][A-Z0-9_]*API[_-]?KEY|api[_ -]?key)\b",
        severity="medium",
        confidence=0.86,
        rationale="Text references an API key or API-key-like environment variable.",
        recommendation="Confirm the tool only requires scoped test credentials and never stores real keys.",
    ),
    SignalRule(
        rule_id="cred_token_001",
        family="credential_reference",
        category="TOKEN",
        pattern=r"\b([A-Z][A-Z0-9_]*TOKEN|access[_ -]?token|bearer token)\b",
        severity="medium",
        confidence=0.84,
        rationale="Text references a token or token-like environment variable.",
        recommendation="Verify token scope and avoid exposing token values to model context.",
    ),
    SignalRule(
        rule_id="cred_secret_001",
        family="credential_reference",
        category="SECRET",
        pattern=r"\b([A-Z][A-Z0-9_]*SECRET|client[_ -]?secret|secret value)\b",
        severity="high",
        confidence=0.86,
        rationale="Text references a secret or secret-like environment variable.",
        recommendation="Keep secret names and values out of generated reports unless redacted.",
    ),
    SignalRule(
        rule_id="cred_password_001",
        family="credential_reference",
        category="PASSWORD",
        pattern=r"\b([A-Z][A-Z0-9_]*PASSWORD|password)\b",
        severity="high",
        confidence=0.86,
        rationale="Text references a password or password-like environment variable.",
        recommendation="Require review before allowing this source into an agent workflow.",
    ),
    SignalRule(
        rule_id="cred_private_key_001",
        family="credential_reference",
        category="PRIVATE_KEY",
        pattern=r"\b([A-Z][A-Z0-9_]*PRIVATE[_-]?KEY|private key)\b",
        severity="critical",
        confidence=0.9,
        rationale="Text references a private key or private-key-like environment variable.",
        recommendation="Block raw private-key material and review whether the tool requires key access.",
    ),
    SignalRule(
        rule_id="perm_filesystem_001",
        family="permission_signal",
        category="filesystem_access",
        pattern=r"\b(read|write|delete|modify|scan)\b.{0,50}\b(files?|filesystem|directories|local paths?)\b|\bfilesystem (read|write|access)\b",
        severity="medium",
        confidence=0.78,
        rationale="Text indicates local filesystem access.",
        recommendation="Confirm the tool has a narrow file allowlist and cannot access secrets.",
    ),
    SignalRule(
        rule_id="perm_network_001",
        family="permission_signal",
        category="network_access",
        pattern=r"\b(network access|http requests?|external endpoints?|webhooks?|callback urls?|send requests?)\b",
        severity="medium",
        confidence=0.78,
        rationale="Text indicates outbound network or external endpoint access.",
        recommendation="Review allowed domains and block unexpected exfiltration paths.",
    ),
    SignalRule(
        rule_id="perm_shell_001",
        family="permission_signal",
        category="shell_execution",
        pattern=r"\b(shell|terminal|command execution|exec|subprocess|bash|powershell)\b",
        severity="high",
        confidence=0.84,
        rationale="Text indicates shell or command execution capability.",
        recommendation="Require explicit approval before allowing shell-capable tools.",
    ),
    SignalRule(
        rule_id="perm_database_001",
        family="permission_signal",
        category="database_access",
        pattern=r"\b(database|postgres|mysql|sqlite|mongodb|sql)\b.{0,50}\b(read|write|query|connect|access)\b|\b(read|write|query|connect|access)\b.{0,50}\b(database|postgres|mysql|sqlite|mongodb|sql)\b",
        severity="medium",
        confidence=0.78,
        rationale="Text indicates database connectivity or query capability.",
        recommendation="Confirm least-privilege database credentials and read/write boundaries.",
    ),
    SignalRule(
        rule_id="perm_email_001",
        family="permission_signal",
        category="email_send",
        pattern=r"\b(send email|email send|smtp|mail delivery)\b",
        severity="medium",
        confidence=0.8,
        rationale="Text indicates email sending capability.",
        recommendation="Require approval before enabling tools that can send messages externally.",
    ),
    SignalRule(
        rule_id="perm_credential_access_001",
        family="permission_signal",
        category="credential_access",
        pattern=r"\b(read|access|load|retrieve)\b.{0,50}\b(credentials?|secrets?|tokens?|passwords?)\b",
        severity="high",
        confidence=0.86,
        rationale="Text indicates direct credential access.",
        recommendation="Block direct credential access unless the need is explicit and sandboxed.",
    ),
    SignalRule(
        rule_id="perm_package_install_001",
        family="permission_signal",
        category="package_install",
        pattern=r"\b(pip install|npm install|package install|install packages?|install dependencies)\b",
        severity="medium",
        confidence=0.8,
        rationale="Text indicates package installation capability.",
        recommendation="Review dependency installation paths and pin trusted package sources.",
    ),
    SignalRule(
        rule_id="perm_code_execution_001",
        family="permission_signal",
        category="code_execution",
        pattern=r"\b(execute code|dynamic code execution|eval\(|run scripts?|execute scripts?)\b",
        severity="high",
        confidence=0.84,
        rationale="Text indicates arbitrary or dynamic code execution capability.",
        recommendation="Require sandboxing and explicit approval before allowing code execution.",
    ),
]


def detect_credential_and_permission_signals(raw_text: str, *, artifact_id: str) -> list[SignalFinding]:
    findings: list[SignalFinding] = []
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        for rule in SIGNAL_RULES:
            if re.search(rule.pattern, line, flags=re.IGNORECASE):
                evidence_span = create_evidence_span(
                    artifact_id=artifact_id,
                    raw_text=raw_text,
                    start_line=line_number,
                    end_line=line_number,
                    span_type=rule.category,
                )
                findings.append(
                    SignalFinding(
                        finding_id=_finding_id(artifact_id, rule.rule_id, evidence_span.span_id),
                        family=rule.family,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        rule_id=rule.rule_id,
                        evidence_span=evidence_span,
                        rationale=rule.rationale,
                        recommendation=rule.recommendation,
                    )
                )
    return findings


def _finding_id(artifact_id: str, rule_id: str, span_id: str) -> str:
    stable_key = f"{artifact_id}:{rule_id}:{span_id}"
    return f"finding_{sha256(stable_key.encode('utf-8')).hexdigest()[:16]}"
