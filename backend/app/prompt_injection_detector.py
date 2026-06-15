from hashlib import sha256
from typing import Literal
import re

from pydantic import BaseModel, Field

from app.evidence import create_evidence_span
from app.models import EvidenceSpan, Severity


InjectionCategory = Literal[
    "instruction_override",
    "secret_exfiltration",
    "tool_misuse",
    "authority_impersonation",
    "persistence_manipulation",
    "suspicious_formatting",
]


class PromptInjectionRule(BaseModel):
    rule_id: str
    category: InjectionCategory
    pattern: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    recommendation: str


class PromptInjectionFinding(BaseModel):
    finding_id: str
    category: InjectionCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str
    evidence_span: EvidenceSpan
    rationale: str
    recommendation: str


PROMPT_INJECTION_RULES = [
    PromptInjectionRule(
        rule_id="pi_instruction_override_001",
        category="instruction_override",
        pattern=r"\b(ignore|disregard|override|bypass)\b.{0,60}\b(previous|prior|above|system|developer|safety)\b.{0,30}\b(instructions?|rules?|message)\b",
        severity="high",
        confidence=0.9,
        rationale="Text appears to ask the model to override higher-priority instructions.",
        recommendation="Quarantine or review this source before exposing it to an agent context.",
    ),
    PromptInjectionRule(
        rule_id="pi_secret_exfiltration_001",
        category="secret_exfiltration",
        pattern=r"\b(reveal|print|dump|send|exfiltrate|upload)\b.{0,80}\b(secrets?|tokens?|api[_ -]?keys?|credentials?|passwords?)\b",
        severity="critical",
        confidence=0.92,
        rationale="Text appears to request disclosure or transfer of secrets or credentials.",
        recommendation="Block the source from agent context and inspect the surrounding artifact.",
    ),
    PromptInjectionRule(
        rule_id="pi_tool_misuse_001",
        category="tool_misuse",
        pattern=r"\b(call|invoke|use|run|execute)\b.{0,80}\b(shell|exec|terminal|curl|wget|delete|rm -rf|filesystem write)\b",
        severity="high",
        confidence=0.86,
        rationale="Text appears to steer the agent toward risky tool use unrelated to normal documentation.",
        recommendation="Require human review before allowing tool execution based on this content.",
    ),
    PromptInjectionRule(
        rule_id="pi_authority_impersonation_001",
        category="authority_impersonation",
        pattern=r"\b(system|developer|admin|root)\b.{0,40}\b(says|message|instruction|requires|orders)\b",
        severity="high",
        confidence=0.84,
        rationale="Text appears to impersonate a higher-priority authority channel.",
        recommendation="Treat this content as untrusted data and do not follow its claimed authority.",
    ),
    PromptInjectionRule(
        rule_id="pi_persistence_manipulation_001",
        category="persistence_manipulation",
        pattern=r"\b(remember|store|persist|always follow|from now on)\b.{0,80}\b(this instruction|these instructions|this rule|future requests?)\b",
        severity="medium",
        confidence=0.82,
        rationale="Text appears to ask the model to retain or prioritize attacker-controlled behavior.",
        recommendation="Strip or isolate this content from any long-lived agent memory.",
    ),
    PromptInjectionRule(
        rule_id="pi_suspicious_formatting_001",
        category="suspicious_formatting",
        pattern=r"(<!--.*?(ignore|disregard|override).*?-->|[\u200b\u200c\u200d\ufeff])",
        severity="medium",
        confidence=0.8,
        rationale="Text contains hidden or obfuscated formatting often used to conceal instructions.",
        recommendation="Render and review the raw source before trusting this artifact.",
    ),
]


def detect_prompt_injection(raw_text: str, *, artifact_id: str) -> list[PromptInjectionFinding]:
    findings: list[PromptInjectionFinding] = []
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        for rule in PROMPT_INJECTION_RULES:
            if re.search(rule.pattern, line, flags=re.IGNORECASE):
                evidence_span = create_evidence_span(
                    artifact_id=artifact_id,
                    raw_text=raw_text,
                    start_line=line_number,
                    end_line=line_number,
                    span_type=rule.category,
                )
                findings.append(
                    PromptInjectionFinding(
                        finding_id=_finding_id(artifact_id, rule.rule_id, evidence_span.span_id),
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
