from types import SimpleNamespace

import pytest

import pipeline.article_processing_service as service
from pipeline.article_processing_service import (
    _validate_article_id,
    analyze_and_save_article,
    enrich_article_cves,
    enrich_article_iocs,
    normalize_and_store_article_iocs,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "article_id",
    [
        1,
        999,
    ],
)
def test_validate_article_id_accepts_positive_integers(
    article_id,
):
    assert _validate_article_id(
        article_id
    ) is None


@pytest.mark.parametrize(
    "article_id",
    [
        None,
        0,
        -1,
        True,
        "1",
        1.0,
    ],
)
def test_validate_article_id_rejects_invalid_values(
    article_id,
):
    with pytest.raises(ValueError) as error_info:
        _validate_article_id(article_id)

    assert str(error_info.value) == (
        "Article ID must be a positive integer."
    )


@pytest.mark.parametrize(
    "article",
    [
        None,
        object(),
        {},
    ],
)
def test_analyze_and_save_article_requires_database_row(
    article,
):
    with pytest.raises(ValueError) as error_info:
        analyze_and_save_article(article)

    assert str(error_info.value) == (
        "A database article row is required."
    )


def test_analyze_and_save_article_validates_row_id():
    article = SimpleNamespace(
        id=True,
    )

    with pytest.raises(ValueError) as error_info:
        analyze_and_save_article(article)

    assert str(error_info.value) == (
        "Article ID must be a positive integer."
    )


def test_analyze_and_save_article_handles_failed_analysis(
    monkeypatch,
):
    article = SimpleNamespace(
        id=101,
        title="Failed analysis",
    )

    monkeypatch.setattr(
        service,
        "analyze_article",
        lambda received_article: None,
    )

    def unexpected_save(analysis):
        raise AssertionError(
            "Failed analysis must not be saved."
        )

    monkeypatch.setattr(
        service,
        "save_article_analysis",
        unexpected_save,
    )

    assert analyze_and_save_article(article) == {
        "article_id": 101,
        "status": "analysis_failed",
        "analysis": None,
    }


def test_analyze_and_save_article_rejects_non_dict_analysis(
    monkeypatch,
):
    article = SimpleNamespace(
        id=102,
    )

    monkeypatch.setattr(
        service,
        "analyze_article",
        lambda received_article: [
            "invalid",
        ],
    )

    with pytest.raises(ValueError) as error_info:
        analyze_and_save_article(article)

    assert str(error_info.value) == (
        "Article analysis must be a dictionary."
    )


def test_analyze_and_save_article_rejects_mismatched_id(
    monkeypatch,
):
    article = SimpleNamespace(
        id=103,
    )

    monkeypatch.setattr(
        service,
        "analyze_article",
        lambda received_article: {
            "article_id": 999,
        },
    )

    with pytest.raises(ValueError) as error_info:
        analyze_and_save_article(article)

    assert str(error_info.value) == (
        "Article analysis ID does not match "
        "the requested article."
    )


def test_analyze_and_save_article_persists_analysis(
    monkeypatch,
):
    article = SimpleNamespace(
        id=104,
    )
    analysis = {
        "article_id": 104,
        "severity": "High",
    }
    captured = {}

    def fake_analyze(received_article):
        captured["article"] = received_article
        return analysis

    def fake_save(received_analysis):
        captured["analysis"] = (
            received_analysis
        )

    monkeypatch.setattr(
        service,
        "analyze_article",
        fake_analyze,
    )
    monkeypatch.setattr(
        service,
        "save_article_analysis",
        fake_save,
    )

    result = analyze_and_save_article(article)

    assert captured["article"] is article
    assert captured["analysis"] is analysis
    assert result == {
        "article_id": 104,
        "status": "analysis_saved",
        "analysis": analysis,
    }


@pytest.mark.parametrize(
    "analysis",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_normalize_and_store_iocs_requires_analysis_dict(
    analysis,
):
    with pytest.raises(ValueError) as error_info:
        normalize_and_store_article_iocs(
            105,
            analysis,
        )

    assert str(error_info.value) == (
        "Article analysis must be a dictionary."
    )


def test_normalize_and_store_iocs_rejects_mismatched_id():
    with pytest.raises(ValueError) as error_info:
        normalize_and_store_article_iocs(
            106,
            {
                "article_id": 999,
            },
        )

    assert str(error_info.value) == (
        "Article analysis ID does not match "
        "the requested article."
    )


def test_normalize_and_store_iocs_handles_missing_iocs(
    monkeypatch,
):
    captured = {}

    def fake_normalize(raw_iocs):
        captured["raw_iocs"] = raw_iocs
        return []

    def fake_replace(
        article_id,
        normalized_iocs,
    ):
        captured["replacement"] = (
            article_id,
            normalized_iocs,
        )
        return {
            "article_id": article_id,
            "deleted_count": 0,
            "inserted_count": 0,
        }

    monkeypatch.setattr(
        service,
        "normalize_ioc_list",
        fake_normalize,
    )
    monkeypatch.setattr(
        service,
        "replace_article_iocs",
        fake_replace,
    )

    result = normalize_and_store_article_iocs(
        107,
        {
            "article_id": 107,
        },
    )

    assert captured["raw_iocs"] == []
    assert captured["replacement"] == (
        107,
        [],
    )
    assert result["raw_ioc_count"] == 0
    assert result["normalized_ioc_count"] == 0


def test_normalize_and_store_iocs_delegates_and_counts(
    monkeypatch,
):
    raw_iocs = [
        "Example[.]COM",
        "example.com",
        "invalid",
    ]
    normalized_iocs = [
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
    ]
    replacement_result = {
        "article_id": 108,
        "deleted_count": 2,
        "inserted_count": 1,
    }
    captured = {}

    def fake_normalize(received_iocs):
        captured["raw_iocs"] = received_iocs
        return normalized_iocs

    def fake_replace(
        article_id,
        received_iocs,
    ):
        captured["replacement"] = (
            article_id,
            received_iocs,
        )
        return replacement_result

    monkeypatch.setattr(
        service,
        "normalize_ioc_list",
        fake_normalize,
    )
    monkeypatch.setattr(
        service,
        "replace_article_iocs",
        fake_replace,
    )

    result = normalize_and_store_article_iocs(
        108,
        {
            "article_id": 108,
            "iocs": raw_iocs,
        },
    )

    assert captured["raw_iocs"] is raw_iocs
    assert captured["replacement"] == (
        108,
        normalized_iocs,
    )

    assert result == {
        "article_id": 108,
        "raw_ioc_count": 3,
        "normalized_ioc_count": 1,
        "normalized_iocs": normalized_iocs,
        "replacement_result": replacement_result,
    }


@pytest.mark.parametrize(
    "normalized_iocs",
    [
        None,
        {},
        "example.com",
        (
            {
                "indicator": "example.com",
            },
        ),
    ],
)
def test_enrich_article_iocs_requires_list(
    normalized_iocs,
):
    with pytest.raises(ValueError) as error_info:
        enrich_article_iocs(
            109,
            normalized_iocs,
        )

    assert str(error_info.value) == (
        "Normalized IOCs must be provided "
        "as a list."
    )


@pytest.mark.parametrize(
    "include_otx",
    [
        None,
        1,
        "true",
    ],
)
def test_enrich_article_iocs_requires_boolean_flag(
    include_otx,
):
    with pytest.raises(ValueError) as error_info:
        enrich_article_iocs(
            110,
            [],
            include_otx=include_otx,
        )

    assert str(error_info.value) == (
        "include_otx must be a boolean."
    )


def test_enrich_article_iocs_returns_disabled(
    monkeypatch,
):
    def unexpected_lookup(iocs):
        raise AssertionError(
            "Disabled OTX must not be called."
        )

    monkeypatch.setattr(
        service,
        "lookup_otx_indicators",
        unexpected_lookup,
    )

    assert enrich_article_iocs(
        111,
        [
            {
                "indicator": "example.com",
                "indicator_type": "domain",
            },
        ],
        include_otx=False,
    ) == {
        "article_id": 111,
        "status": "disabled",
        "lookup_count": 0,
        "successful_lookup_count": 0,
        "failed_lookup_count": 0,
        "results": [],
    }


def test_enrich_article_iocs_handles_empty_list(
    monkeypatch,
):
    def unexpected_lookup(iocs):
        raise AssertionError(
            "Empty IOC list must not call OTX."
        )

    monkeypatch.setattr(
        service,
        "lookup_otx_indicators",
        unexpected_lookup,
    )

    assert enrich_article_iocs(
        112,
        [],
        include_otx=True,
    ) == {
        "article_id": 112,
        "status": "no_iocs",
        "lookup_count": 0,
        "successful_lookup_count": 0,
        "failed_lookup_count": 0,
        "results": [],
    }


def test_enrich_article_iocs_counts_lookup_results(
    monkeypatch,
):
    normalized_iocs = [
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
        {
            "indicator": "192.0.2.10",
            "indicator_type": "IPv4",
        },
        {
            "indicator": "test.example",
            "indicator_type": "domain",
        },
    ]

    lookup_results = [
        {
            "pulse_count": 2,
        },
        None,
        {
            "pulse_count": 0,
        },
    ]
    captured = {}

    def fake_lookup(received_iocs):
        captured["iocs"] = received_iocs
        return lookup_results

    monkeypatch.setattr(
        service,
        "lookup_otx_indicators",
        fake_lookup,
    )

    result = enrich_article_iocs(
        113,
        normalized_iocs,
        include_otx=True,
    )

    assert captured["iocs"] is normalized_iocs
    assert result == {
        "article_id": 113,
        "status": "completed",
        "lookup_count": 3,
        "successful_lookup_count": 2,
        "failed_lookup_count": 1,
        "results": lookup_results,
    }


@pytest.mark.parametrize(
    "analysis",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_enrich_article_cves_requires_analysis_dict(
    analysis,
):
    with pytest.raises(ValueError) as error_info:
        enrich_article_cves(
            201,
            analysis,
        )

    assert str(error_info.value) == (
        "Article analysis must be a dictionary."
    )


def test_enrich_article_cves_rejects_mismatched_id():
    with pytest.raises(ValueError) as error_info:
        enrich_article_cves(
            202,
            {
                "article_id": 999,
                "cves": [],
            },
        )

    assert str(error_info.value) == (
        "Article analysis ID does not match "
        "the requested article."
    )


@pytest.mark.parametrize(
    "include_cve",
    [
        None,
        1,
        "true",
    ],
)
def test_enrich_article_cves_requires_boolean_flag(
    include_cve,
):
    with pytest.raises(ValueError) as error_info:
        enrich_article_cves(
            203,
            {
                "article_id": 203,
                "cves": [],
            },
            include_cve=include_cve,
        )

    assert str(error_info.value) == (
        "include_cve must be a boolean."
    )


@pytest.mark.parametrize(
    "cves",
    [
        None,
        {},
        "CVE-2026-1001",
        (
            "CVE-2026-1001",
        ),
    ],
)
def test_enrich_article_cves_requires_cve_list(
    cves,
):
    with pytest.raises(ValueError) as error_info:
        enrich_article_cves(
            204,
            {
                "article_id": 204,
                "cves": cves,
            },
        )

    assert str(error_info.value) == (
        "Article CVEs must be provided as a list."
    )


@pytest.mark.parametrize(
    "invalid_cve",
    [
        None,
        123,
        "",
        "   ",
    ],
)
def test_enrich_article_cves_rejects_invalid_cve_ids(
    invalid_cve,
):
    with pytest.raises(ValueError) as error_info:
        enrich_article_cves(
            205,
            {
                "article_id": 205,
                "cves": [
                    "CVE-2026-1001",
                    invalid_cve,
                ],
            },
        )

    assert str(error_info.value) == (
        "Each CVE ID must be a non-empty string."
    )


def test_enrich_article_cves_returns_disabled(
    monkeypatch,
):
    def unexpected_lookup(cve_id):
        raise AssertionError(
            "Disabled CVE enrichment must not "
            "perform lookups."
        )

    monkeypatch.setattr(
        service,
        "lookup_cve",
        unexpected_lookup,
    )

    result = enrich_article_cves(
        206,
        {
            "article_id": 206,
            "cves": [
                "CVE-2026-1001",
                "CVE-2026-1001",
            ],
        },
        include_cve=False,
    )

    assert result == {
        "article_id": 206,
        "status": "disabled",
        "requested_cve_count": 2,
        "lookup_count": 0,
        "available_count": 0,
        "unavailable_count": 0,
        "failed_count": 0,
        "results": [],
    }


def test_enrich_article_cves_handles_empty_list(
    monkeypatch,
):
    def unexpected_lookup(cve_id):
        raise AssertionError(
            "Empty CVE list must not perform "
            "lookups."
        )

    monkeypatch.setattr(
        service,
        "lookup_cve",
        unexpected_lookup,
    )

    result = enrich_article_cves(
        207,
        {
            "article_id": 207,
            "cves": [],
        },
        include_cve=True,
    )

    assert result == {
        "article_id": 207,
        "status": "no_cves",
        "requested_cve_count": 0,
        "lookup_count": 0,
        "available_count": 0,
        "unavailable_count": 0,
        "failed_count": 0,
        "results": [],
    }


def test_enrich_article_cves_deduplicates_and_isolates_failures(
    monkeypatch,
):
    calls = []

    available_details = {
        "cve_id": "CVE-2026-1001",
        "cvss_score": 9.8,
    }

    def fake_lookup(cve_id):
        calls.append(cve_id)

        if cve_id == "CVE-2026-1001":
            return available_details

        if cve_id == "CVE-2026-1002":
            return None

        raise RuntimeError(
            "Simulated NVD failure"
        )

    monkeypatch.setattr(
        service,
        "lookup_cve",
        fake_lookup,
    )

    result = enrich_article_cves(
        208,
        {
            "article_id": 208,
            "cves": [
                "CVE-2026-1001",
                "CVE-2026-1001",
                "CVE-2026-1002",
                "CVE-2026-1003",
            ],
        },
        include_cve=True,
    )

    assert calls == [
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1003",
    ]

    assert result == {
        "article_id": 208,
        "status": "completed",
        "requested_cve_count": 4,
        "lookup_count": 3,
        "available_count": 1,
        "unavailable_count": 1,
        "failed_count": 1,
        "results": [
            {
                "cve_id": "CVE-2026-1001",
                "enrichment_available": True,
                "details": available_details,
                "error": None,
            },
            {
                "cve_id": "CVE-2026-1002",
                "enrichment_available": False,
                "details": None,
                "error": None,
            },
            {
                "cve_id": "CVE-2026-1003",
                "enrichment_available": False,
                "details": None,
                "error": (
                    "RuntimeError: "
                    "Simulated NVD failure"
                ),
            },
        ],
    }


def _install_successful_process_dependencies(
    monkeypatch,
    article_id=301,
):
    events = []

    article = SimpleNamespace(
        id=article_id,
        title="Controlled article",
    )

    analysis = {
        "article_id": article_id,
        "iocs": ["8.8.8.8"],
        "cves": ["CVE-2026-1001"],
    }

    ioc_processing = {
        "article_id": article_id,
        "raw_ioc_count": 1,
        "normalized_ioc_count": 1,
        "normalized_iocs": [
            {
                "indicator": "8.8.8.8",
                "indicator_type": "IPv4",
            },
        ],
        "replacement_result": {
            "inserted_count": 1,
        },
    }

    def fake_analyze(received_article):
        events.append("analysis")

        assert received_article is article

        return {
            "article_id": article_id,
            "status": "analysis_saved",
            "analysis": analysis,
        }

    def fake_normalize(
        received_article_id,
        received_analysis,
    ):
        events.append("ioc_processing")

        assert received_article_id == article_id
        assert received_analysis is analysis

        return ioc_processing

    def fake_otx(
        received_article_id,
        normalized_iocs,
        include_otx=True,
    ):
        events.append(
            (
                "otx",
                include_otx,
            )
        )

        assert received_article_id == article_id
        assert normalized_iocs == (
            ioc_processing["normalized_iocs"]
        )

        return {
            "article_id": article_id,
            "status": "completed",
            "lookup_count": 1,
            "successful_lookup_count": 1,
            "failed_lookup_count": 0,
            "results": [
                {
                    "pulse_count": 2,
                },
            ],
        }

    def fake_cve(
        received_article_id,
        received_analysis,
        include_cve=True,
    ):
        events.append(
            (
                "cve",
                include_cve,
            )
        )

        assert received_article_id == article_id
        assert received_analysis is analysis

        return {
            "article_id": article_id,
            "status": "completed",
            "requested_cve_count": 1,
            "lookup_count": 1,
            "available_count": 1,
            "unavailable_count": 0,
            "failed_count": 0,
            "results": [
                {
                    "cve_id": "CVE-2026-1001",
                    "enrichment_available": True,
                    "details": {
                        "cvss_score": 9.8,
                    },
                    "error": None,
                },
            ],
        }

    def fake_index(received_article_id):
        events.append("embedding")

        assert received_article_id == article_id

        return {
            "article_id": article_id,
            "status": "updated",
        }

    def fake_mark(received_article_id):
        events.append("marked_processed")

        assert received_article_id == article_id

    monkeypatch.setattr(
        service,
        "analyze_and_save_article",
        fake_analyze,
    )
    monkeypatch.setattr(
        service,
        "normalize_and_store_article_iocs",
        fake_normalize,
    )
    monkeypatch.setattr(
        service,
        "enrich_article_iocs",
        fake_otx,
    )
    monkeypatch.setattr(
        service,
        "enrich_article_cves",
        fake_cve,
    )
    monkeypatch.setattr(
        service,
        "index_article",
        fake_index,
    )
    monkeypatch.setattr(
        service,
        "mark_article_as_processed",
        fake_mark,
    )

    return {
        "article": article,
        "analysis": analysis,
        "ioc_processing": ioc_processing,
        "events": events,
    }


@pytest.mark.parametrize(
    (
        "options",
        "expected_message",
    ),
    [
        (
            {
                "include_otx": None,
                "include_cve": True,
            },
            "include_otx must be a boolean.",
        ),
        (
            {
                "include_otx": 1,
                "include_cve": True,
            },
            "include_otx must be a boolean.",
        ),
        (
            {
                "include_otx": "true",
                "include_cve": True,
            },
            "include_otx must be a boolean.",
        ),
        (
            {
                "include_otx": True,
                "include_cve": None,
            },
            "include_cve must be a boolean.",
        ),
        (
            {
                "include_otx": True,
                "include_cve": 1,
            },
            "include_cve must be a boolean.",
        ),
        (
            {
                "include_otx": True,
                "include_cve": "true",
            },
            "include_cve must be a boolean.",
        ),
    ],
)
def test_process_article_rejects_invalid_options(
    options,
    expected_message,
):
    with pytest.raises(ValueError) as error_info:
        service.process_article(
            SimpleNamespace(
                id=301,
            ),
            **options,
        )

    assert str(error_info.value) == (
        expected_message
    )


def test_process_article_stops_after_failed_analysis(
    monkeypatch,
):
    article = SimpleNamespace(
        id=302,
        title="Failed analysis",
    )

    monkeypatch.setattr(
        service,
        "analyze_and_save_article",
        lambda received_article: {
            "article_id": 302,
            "status": "analysis_failed",
            "analysis": None,
        },
    )

    def unexpected_call(*args, **kwargs):
        raise AssertionError(
            "Downstream processing must not run."
        )

    monkeypatch.setattr(
        service,
        "normalize_and_store_article_iocs",
        unexpected_call,
    )
    monkeypatch.setattr(
        service,
        "enrich_article_iocs",
        unexpected_call,
    )
    monkeypatch.setattr(
        service,
        "enrich_article_cves",
        unexpected_call,
    )
    monkeypatch.setattr(
        service,
        "index_article",
        unexpected_call,
    )
    monkeypatch.setattr(
        service,
        "mark_article_as_processed",
        unexpected_call,
    )

    result = service.process_article(article)

    assert result == {
        "article_id": 302,
        "status": "analysis_failed",
        "analysis": None,
        "ioc_processing": None,
        "otx_enrichment": None,
        "cve_enrichment": None,
        "embedding_status": "deferred",
        "marked_processed": False,
        "warnings": [
            (
                "The AI analysis did not produce "
                "a safe result."
            ),
        ],
    }


def test_process_article_completes_successfully(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=303,
        )
    )

    result = service.process_article(
        controlled["article"],
        include_otx=False,
        include_cve=False,
    )

    assert result["article_id"] == 303
    assert result["status"] == "processed"
    assert result["analysis"] is (
        controlled["analysis"]
    )
    assert result["ioc_processing"] is (
        controlled["ioc_processing"]
    )
    assert result["embedding_status"] == "updated"
    assert result["marked_processed"] is True
    assert result["warnings"] == []

    assert controlled["events"] == [
        "analysis",
        "ioc_processing",
        (
            "otx",
            False,
        ),
        (
            "cve",
            False,
        ),
        "embedding",
        "marked_processed",
    ]


def test_process_article_isolates_otx_exception(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=304,
        )
    )

    def failing_otx(*args, **kwargs):
        raise RuntimeError(
            "OTX unavailable"
        )

    monkeypatch.setattr(
        service,
        "enrich_article_iocs",
        failing_otx,
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["otx_enrichment"] == {
        "article_id": 304,
        "status": "failed",
        "lookup_count": 0,
        "successful_lookup_count": 0,
        "failed_lookup_count": 0,
        "results": [],
        "error": (
            "RuntimeError: OTX unavailable"
        ),
    }
    assert result["warnings"] == [
        "OTX enrichment failed unexpectedly.",
    ]
    assert result["marked_processed"] is True


def test_process_article_warns_about_missing_otx_results(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=305,
        )
    )

    monkeypatch.setattr(
        service,
        "enrich_article_iocs",
        lambda *args, **kwargs: {
            "article_id": 305,
            "status": "completed",
            "lookup_count": 2,
            "successful_lookup_count": 1,
            "failed_lookup_count": 1,
            "results": [
                {
                    "pulse_count": 2,
                },
                None,
            ],
        },
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["warnings"] == [
        (
            "One or more OTX lookups "
            "returned no enrichment."
        ),
    ]


def test_process_article_isolates_cve_exception(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=306,
        )
    )

    def failing_cve(*args, **kwargs):
        raise RuntimeError(
            "NVD unavailable"
        )

    monkeypatch.setattr(
        service,
        "enrich_article_cves",
        failing_cve,
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["cve_enrichment"] == {
        "article_id": 306,
        "status": "failed",
        "requested_cve_count": 0,
        "lookup_count": 0,
        "available_count": 0,
        "unavailable_count": 0,
        "failed_count": 0,
        "results": [],
        "error": (
            "RuntimeError: NVD unavailable"
        ),
    }
    assert result["warnings"] == [
        "CVE enrichment failed unexpectedly.",
    ]
    assert result["marked_processed"] is True


def test_process_article_warns_about_failed_cve_lookups(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=307,
        )
    )

    monkeypatch.setattr(
        service,
        "enrich_article_cves",
        lambda *args, **kwargs: {
            "article_id": 307,
            "status": "completed",
            "requested_cve_count": 1,
            "lookup_count": 1,
            "available_count": 0,
            "unavailable_count": 0,
            "failed_count": 1,
            "results": [],
        },
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["warnings"] == [
        "One or more CVE lookups failed.",
    ]


def test_process_article_isolates_embedding_exception(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=308,
        )
    )

    def failing_embedding(article_id):
        raise RuntimeError(
            "Embedding model unavailable"
        )

    monkeypatch.setattr(
        service,
        "index_article",
        failing_embedding,
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["embedding_status"] == "failed"
    assert result["embedding_result"] == {
        "article_id": 308,
        "status": "failed",
        "error": (
            "RuntimeError: "
            "Embedding model unavailable"
        ),
    }
    assert result["warnings"] == [
        "Article embedding refresh failed.",
    ]
    assert result["marked_processed"] is True


def test_process_article_handles_invalid_embedding_result(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=309,
        )
    )

    monkeypatch.setattr(
        service,
        "index_article",
        lambda article_id: None,
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["embedding_status"] == "failed"
    assert result["embedding_result"] == {
        "article_id": 309,
        "status": "failed",
        "error": (
            "Embedding service returned "
            "an invalid result."
        ),
    }
    assert result["warnings"] == [
        (
            "Article embedding refresh did "
            "not complete successfully."
        ),
    ]


def test_process_article_warns_about_unsuccessful_embedding(
    monkeypatch,
):
    controlled = (
        _install_successful_process_dependencies(
            monkeypatch,
            article_id=310,
        )
    )

    monkeypatch.setattr(
        service,
        "index_article",
        lambda article_id: {
            "article_id": article_id,
            "status": "not_found",
        },
    )

    result = service.process_article(
        controlled["article"]
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["embedding_status"] == (
        "not_found"
    )
    assert result["warnings"] == [
        (
            "Article embedding refresh did "
            "not complete successfully."
        ),
    ]
    assert result["marked_processed"] is True
