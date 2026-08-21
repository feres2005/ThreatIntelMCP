import json
from types import SimpleNamespace

import pytest

import ai.analyzer as service


pytestmark = pytest.mark.unit


def _article(article_id=401):
    return SimpleNamespace(
        id=article_id,
        title="Controlled threat article",
        summary=(
            "ControlledMalware exploited "
            "CVE-2026-1001."
        ),
    )


def _valid_analysis():
    return {
        "summary": "Controlled summary.",
        "classification": [
            "malware",
        ],
        "severity": "High",
        "confidence_score": 0.85,
        "iocs": [],
        "cves": [
            "CVE-2026-1001",
        ],
        "malware": [
            "ControlledMalware",
        ],
        "mitre_techniques": [],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": [],
    }


def _text_response(text):
    return SimpleNamespace(
        content=[
            SimpleNamespace(
                type="text",
                text=text,
            ),
        ],
    )


def _install_client(
    monkeypatch,
    create_function,
):
    monkeypatch.setattr(
        service,
        "client",
        SimpleNamespace(
            messages=SimpleNamespace(
                create=create_function,
            ),
        ),
    )


def test_build_analysis_prompt_contains_article_and_rules():
    article = _article()

    prompt = service.build_analysis_prompt(
        article
    )

    assert article.title in prompt
    assert article.summary in prompt
    assert "Return ONLY a valid JSON object." in prompt
    assert '"confidence_score": 0.0' in prompt
    assert "CVE identifiers" in prompt
    assert "MITRE ATT&CK technique ID" in prompt

    for classification in (
        "malware",
        "ransomware",
        "APT",
        "ICS-attack",
    ):
        assert classification in prompt


def test_build_correction_prompt_contains_response_and_errors():
    original_response = (
        '{"severity": "Severe"}'
    )
    validation_errors = {
        "invalid_severity": "Severe",
    }

    prompt = service.build_correction_prompt(
        original_response,
        validation_errors,
    )

    assert original_response in prompt
    assert '"invalid_severity": "Severe"' in prompt
    assert "fix only the invalid or missing parts" in prompt
    assert "return ONLY valid raw JSON" in prompt
    assert "do not use code fences" in prompt


def test_regenerate_analysis_returns_corrected_text(
    monkeypatch,
):
    calls = []

    def fake_create(**kwargs):
        calls.append(kwargs)

        return _text_response(
            '{"severity": "High"}'
        )

    _install_client(
        monkeypatch,
        fake_create,
    )

    result = service.regenerate_analysis(
        '{"severity": "Severe"}',
        {
            "invalid_severity": "Severe",
        },
    )

    assert result == '{"severity": "High"}'
    assert len(calls) == 1

    request = calls[0]

    assert request["model"] == (
        "claude-haiku-4-5-20251001"
    )
    assert request["max_tokens"] == 500
    assert request["messages"][0]["role"] == "user"
    assert (
        '"invalid_severity": "Severe"'
        in request["messages"][0]["content"]
    )


def test_regenerate_analysis_handles_api_failure(
    monkeypatch,
    caplog,
):
    def failing_create(**kwargs):
        raise RuntimeError(
            "Controlled correction failure"
        )

    _install_client(
        monkeypatch,
        failing_create,
    )

    result = service.regenerate_analysis(
        "{}",
        {
            "missing_fields": [
                "summary",
            ],
        },
    )

    assert result is None
    assert (
        "Claude API error during correction"
        in caplog.text
    )


def test_regenerate_analysis_handles_empty_response(
    monkeypatch,
):
    _install_client(
        monkeypatch,
        lambda **kwargs: SimpleNamespace(
            content=[],
        ),
    )

    result = service.regenerate_analysis(
        "{}",
        {
            "missing_fields": [
                "summary",
            ],
        },
    )

    assert result is None


def test_analyze_article_handles_initial_api_failure(
    monkeypatch,
    caplog,
):
    def failing_create(**kwargs):
        raise RuntimeError(
            "Controlled initial failure"
        )

    _install_client(
        monkeypatch,
        failing_create,
    )

    result = service.analyze_article(
        _article()
    )

    assert result is None
    assert (
        "Claude API error during initial analysis"
        in caplog.text
    )


def test_analyze_article_handles_missing_text(
    monkeypatch,
):
    _install_client(
        monkeypatch,
        lambda **kwargs: SimpleNamespace(
            content=[],
        ),
    )

    assert service.analyze_article(
        _article()
    ) is None


def test_analyze_article_accepts_first_valid_response(
    monkeypatch,
):
    calls = []
    analysis = _valid_analysis()
    article = _article(
        article_id=402,
    )

    def fake_create(**kwargs):
        calls.append(kwargs)

        return _text_response(
            json.dumps(analysis)
        )

    _install_client(
        monkeypatch,
        fake_create,
    )

    result = service.analyze_article(
        article
    )

    assert result == {
        **analysis,
        "article_id": 402,
    }
    assert len(calls) == 1

    request = calls[0]

    assert request["model"] == (
        "claude-haiku-4-5-20251001"
    )
    assert request["max_tokens"] == 500
    assert article.title in (
        request["messages"][0]["content"]
    )


def test_analyze_article_accepts_corrected_retry(
    monkeypatch,
):
    bad_analysis = _valid_analysis()
    bad_analysis["severity"] = "Severe"

    corrected_analysis = _valid_analysis()

    responses = iter([
        _text_response(
            json.dumps(bad_analysis)
        ),
        _text_response(
            json.dumps(corrected_analysis)
        ),
    ])

    calls = []

    def fake_create(**kwargs):
        calls.append(kwargs)
        return next(responses)

    _install_client(
        monkeypatch,
        fake_create,
    )

    result = service.analyze_article(
        _article(
            article_id=403,
        )
    )

    assert result == {
        **corrected_analysis,
        "article_id": 403,
    }
    assert len(calls) == 2

    correction_prompt = (
        calls[1]["messages"][0]["content"]
    )

    assert "invalid_severity" in (
        correction_prompt
    )


def test_analyze_article_stops_after_unavailable_retries(
    monkeypatch,
):
    _install_client(
        monkeypatch,
        lambda **kwargs: _text_response(
            "{invalid-json"
        ),
    )

    retry_calls = []

    def unavailable_retry(
        original_response,
        validation_errors,
    ):
        retry_calls.append({
            "response": original_response,
            "errors": validation_errors,
        })
        return None

    monkeypatch.setattr(
        service,
        "regenerate_analysis",
        unavailable_retry,
    )

    result = service.analyze_article(
        _article()
    )

    assert result is None
    assert len(retry_calls) == (
        service.MAX_RETRIES
    )

    assert all(
        call["errors"] == {
            "invalid_json": (
                "Claude response could not "
                "be parsed as JSON"
            ),
        }
        for call in retry_calls
    )


def test_analyze_article_rejects_structural_errors_after_retries(
    monkeypatch,
):
    responses = iter([
        _text_response("[1, 2]"),
        _text_response("[3, 4]"),
        _text_response("[5, 6]"),
    ])

    calls = []

    def fake_create(**kwargs):
        calls.append(kwargs)
        return next(responses)

    _install_client(
        monkeypatch,
        fake_create,
    )

    result = service.analyze_article(
        _article()
    )

    assert result is None
    assert len(calls) == (
        service.MAX_RETRIES + 1
    )


def test_analyze_article_applies_safe_semantic_defaults(
    monkeypatch,
):
    bad_analysis = _valid_analysis()

    bad_analysis["classification"] = [
        "malware",
        "unsupported",
    ]
    bad_analysis["severity"] = "Severe"
    bad_analysis["confidence_score"] = 4
    bad_analysis["cves"] = [
        "CVE-2026-1001",
        "invalid-cve",
    ]
    bad_analysis["mitre_techniques"] = [
        "T1566.002",
        "invalid-technique",
    ]

    responses = iter([
        _text_response(
            json.dumps(bad_analysis)
        )
        for _ in range(
            service.MAX_RETRIES + 1
        )
    ])

    calls = []

    def fake_create(**kwargs):
        calls.append(kwargs)
        return next(responses)

    _install_client(
        monkeypatch,
        fake_create,
    )

    result = service.analyze_article(
        _article(
            article_id=404,
        )
    )

    assert result["article_id"] == 404
    assert result["classification"] == [
        "malware",
    ]
    assert result["severity"] == "None"
    assert result["confidence_score"] == 0.0
    assert result["cves"] == [
        "CVE-2026-1001",
    ]
    assert result["mitre_techniques"] == [
        "T1566.002",
    ]

    assert len(calls) == (
        service.MAX_RETRIES + 1
    )
