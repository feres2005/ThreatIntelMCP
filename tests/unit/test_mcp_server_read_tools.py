import asyncio

import pytest

import mcp_server.server as service


pytestmark = pytest.mark.unit


def test_ping_returns_server_status():
    assert service.ping() == (
        "ThreatIntelMCP is running"
    )


@pytest.mark.parametrize(
    (
        "tool_name",
        "dependency_name",
        "arguments",
        "keyword_arguments",
    ),
    [
        (
            "search_threat_articles",
            "search_articles",
            (
                "malware",
            ),
            {},
        ),
        (
            "get_threat_article_details",
            "get_article_details",
            (
                701,
            ),
            {},
        ),
        (
            "search_cves",
            "search_cves_db",
            (
                "CVE-2026",
            ),
            {},
        ),
        (
            "get_cve_supporting_articles",
            "get_cve_supporting_articles_db",
            (
                "CVE-2026-50522",
            ),
            {
                "limit": 7,
            },
        ),
        (
            "search_malware",
            "search_malware_db",
            (
                "ControlledMalware",
            ),
            {},
        ),
        (
            "search_mitre",
            "search_mitre_db",
            (
                "T1566",
            ),
            {},
        ),
        (
            "search_apt_groups",
            "search_apt_groups_db",
            (
                "APT29",
            ),
            {},
        ),
        (
            "search_targeted_sectors",
            "search_targeted_sectors_db",
            (
                "Finance",
            ),
            {},
        ),
        (
            "search_affected_technologies",
            (
                "search_affected_"
                "technologies_db"
            ),
            (
                "Windows",
            ),
            {},
        ),
        (
            "search_github_advisories",
            "search_github_advisories_db",
            (
                "GHSA",
            ),
            {},
        ),
        (
            "get_github_advisory_details",
            "get_github_advisory_details_db",
            (
                "GHSA-AAAA-BBBB-CCCC",
            ),
            {},
        ),
        (
            (
                "get_github_advisory_"
                "supporting_articles"
            ),
            "get_ghsa_supporting_articles_db",
            (
                "GHSA-v667-gc2r-2xm7",
            ),
            {
                "limit": 8,
            },
        ),
        (
            "search_mitre_techniques",
            "search_mitre_techniques_db",
            (
                "Phishing",
            ),
            {},
        ),
        (
            "get_mitre_technique_details",
            "get_mitre_technique_details_db",
            (
                "T1566",
            ),
            {},
        ),
        (
            (
                "get_mitre_technique_"
                "supporting_articles"
            ),
            "get_mitre_supporting_articles_db",
            (
                "T1566.002",
            ),
            {
                "limit": 9,
            },
        ),
        (
            "lookup_otx_indicator",
            "lookup_otx_indicator_service",
            (
                "8.8.8.8",
                "IPv4",
            ),
            {},
        ),
        (
            "correlate_threat_indicator",
            "correlate_indicator_service",
            (
                "8.8.8.8",
            ),
            {
                "include_otx": False,
            },
        ),
        (
            "investigate_threat_article",
            (
                "get_article_"
                "investigation_service"
            ),
            (
                702,
            ),
            {
                "include_otx": False,
            },
        ),
        (
            "score_threat_article",
            "score_article_service",
            (
                703,
            ),
            {
                "include_otx": True,
            },
        ),
        (
            "score_threat_indicator",
            "score_indicator_service",
            (
                "example.com",
            ),
            {
                "include_otx": False,
            },
        ),
                (
            "get_emerging_threat_topics",
            "detect_emerging_topics_service",
            (),
            {
                "observation_days": 30,
                "recent_days": 7,
                "limit": 10,
            },
        ),
        (
            "get_pipeline_status",
            "get_pipeline_status_service",
            (),
            {},
        ),
    ],
)
def test_read_only_tool_delegates_to_service(
    monkeypatch,
    tool_name,
    dependency_name,
    arguments,
    keyword_arguments,
):
    calls = []

    expected_result = {
        "controlled_tool": tool_name,
    }

    def fake_dependency(
        *received_arguments,
        **received_keyword_arguments,
    ):
        calls.append({
            "arguments": received_arguments,
            "keyword_arguments": (
                received_keyword_arguments
            ),
        })

        return expected_result

    monkeypatch.setattr(
        service,
        dependency_name,
        fake_dependency,
    )

    tool = getattr(
        service,
        tool_name,
    )

    result = tool(
        *arguments,
        **keyword_arguments,
    )


    assert result is expected_result
    assert calls == [
        {
            "arguments": arguments,
            "keyword_arguments": (
                keyword_arguments
            ),
        },
    ]


def test_semantic_search_tool_awaits_worker(
    monkeypatch,
):
    calls = []

    expected_result = [
        {
            "article_id": 704,
            "similarity": 0.92,
        },
    ]

    async def fake_worker(
        search_query,
        limit,
    ):
        calls.append({
            "search_query": search_query,
            "limit": limit,
        })

        return expected_result

    monkeypatch.setattr(
        service,
        "run_semantic_search_worker",
        fake_worker,
    )

    result = asyncio.run(
        service.semantic_search_threat_articles(
            "ransomware targeting hospitals",
            limit=4,
        )
    )

    assert result is expected_result
    assert calls == [
        {
            "search_query": (
                "ransomware targeting hospitals"
            ),
            "limit": 4,
        },
    ]


def test_cve_detail_tool_runs_lookup_in_thread(
    monkeypatch,
):
    calls = []

    expected_result = {
        "cve_id": "CVE-2026-1001",
        "cvss_score": 9.8,
    }

    def fake_lookup(cve_id):
        raise AssertionError(
            "The controlled to_thread helper "
            "must receive the lookup function."
        )

    async def fake_to_thread(
        function,
        *arguments,
    ):
        calls.append({
            "function": function,
            "arguments": arguments,
        })

        return expected_result

    monkeypatch.setattr(
        service,
        "lookup_cve",
        fake_lookup,
    )
    monkeypatch.setattr(
        service.asyncio,
        "to_thread",
        fake_to_thread,
    )

    result = asyncio.run(
        service.get_cve_details(
            "CVE-2026-1001"
        )
    )

    assert result is expected_result
    assert calls == [
        {
            "function": fake_lookup,
            "arguments": (
                "CVE-2026-1001",
            ),
        },
    ]
