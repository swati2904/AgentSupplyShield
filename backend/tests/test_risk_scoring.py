from app.risk_scoring import assess_risk, policy_decision_for_level, risk_level_for_score


def test_low_risk_allows_clean_or_low_signal_input() -> None:
    assessment = assess_risk([{"finding_id": "finding_low", "severity": "low", "confidence": 0.8}])

    assert assessment.risk_score == 8
    assert assessment.risk_level == "low"
    assert assessment.policy_decision == "allow"
    assert assessment.severity_counts["low"] == 1


def test_medium_risk_warns_for_medium_signal() -> None:
    assessment = assess_risk([{"finding_id": "finding_medium", "severity": "medium", "confidence": 1.0}])

    assert assessment.risk_score == 35
    assert assessment.risk_level == "medium"
    assert assessment.policy_decision == "warn"
    assert assessment.contributions[0].points == 35


def test_high_risk_quarantines_for_high_signal() -> None:
    assessment = assess_risk([{"finding_id": "finding_high", "severity": "high", "confidence": 1.0}])

    assert assessment.risk_score == 65
    assert assessment.risk_level == "high"
    assert assessment.policy_decision == "quarantine"
    assert assessment.severity_counts["high"] == 1


def test_critical_risk_blocks_and_score_is_capped() -> None:
    assessment = assess_risk(
        [
            {"finding_id": "finding_critical_1", "severity": "critical", "confidence": 1.0},
            {"finding_id": "finding_critical_2", "severity": "critical", "confidence": 1.0},
        ]
    )

    assert assessment.risk_score == 100
    assert assessment.risk_level == "critical"
    assert assessment.policy_decision == "block"
    assert assessment.severity_counts["critical"] == 2


def test_score_and_policy_boundary_helpers_are_deterministic() -> None:
    assert risk_level_for_score(0) == "low"
    assert risk_level_for_score(25) == "medium"
    assert risk_level_for_score(50) == "high"
    assert risk_level_for_score(75) == "critical"
    assert policy_decision_for_level("low") == "allow"
    assert policy_decision_for_level("medium") == "warn"
    assert policy_decision_for_level("high") == "quarantine"
    assert policy_decision_for_level("critical") == "block"
