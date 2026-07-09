import backend_release_ready as gate


def test_blocked_release_cannot_publish():
    problems = gate.failures({
        "status": "blocked",
        "gates": {"review": {"passed": False, "evidence": ""}},
    })
    assert "release status is not ready" in problems
    assert "gate is not passed: review" in problems


def test_ready_release_requires_evidence_for_every_gate():
    assert gate.failures({
        "status": "ready",
        "gates": {"review": {"passed": True, "evidence": "audit/report.pdf"}},
    }) == []
    assert gate.failures({
        "status": "ready",
        "gates": {"review": {"passed": True, "evidence": ""}},
    }) == ["gate has no evidence: review"]
