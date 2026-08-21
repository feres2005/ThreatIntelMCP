import pytest

import mcp_server.server as service


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "confirm",
    [
        None,
        0,
        1,
        "true",
        [],
    ],
)
def test_confirmation_rejects_non_boolean_values(
    confirm,
):
    with pytest.raises(ValueError) as error_info:
        service._get_confirmation_response(
            "controlled_operation",
            confirm,
        )

    assert str(error_info.value) == (
        "confirm must be a boolean."
    )


def test_confirmation_allows_explicit_true():
    assert service._get_confirmation_response(
        "controlled_operation",
        True,
    ) is None


def test_confirmation_returns_safe_response_for_false():
    result = service._get_confirmation_response(
        "controlled_operation",
        False,
    )

    assert result == {
        "operation": "controlled_operation",
        "status": "confirmation_required",
        "message": (
            "Explicit confirmation is required "
            "before this operation can run."
        ),
    }


@pytest.mark.parametrize(
    (
        "tool_name",
        "dependency_name",
        "operation",
        "tool_arguments",
    ),
    [
        (
            "ingest_rss_articles",
            "ingest_rss_articles_service",
            "ingest_rss_articles",
            {},
        ),
        (
            "process_pending_articles",
            "process_pending_articles_service",
            "process_pending_articles",
            {
                "limit": 7,
                "include_otx": True,
                "include_cve": True,
            },
        ),
        (
            "index_pending_embeddings",
            "index_pending_embeddings_service",
            "index_pending_embeddings",
            {
                "limit": 12,
            },
        ),
        (
            "synchronize_mitre_intelligence",
            (
                "synchronize_mitre_"
                "intelligence_service"
            ),
            "synchronize_mitre_intelligence",
            {
                "domains": [
                    "enterprise-attack",
                    "ics-attack",
                ],
            },
        ),
        (
            "synchronize_github_intelligence",
            (
                "synchronize_github_"
                "intelligence_service"
            ),
            "synchronize_github_intelligence",
            {},
        ),
    ],
)
def test_mutating_tools_require_confirmation(
    monkeypatch,
    tool_name,
    dependency_name,
    operation,
    tool_arguments,
):
    def unexpected_service_call(
        *args,
        **kwargs,
    ):
        raise AssertionError(
            "Mutation service must not run "
            "without confirmation."
        )

    monkeypatch.setattr(
        service,
        dependency_name,
        unexpected_service_call,
    )

    tool = getattr(
        service,
        tool_name,
    )

    result = tool(
        **tool_arguments
    )

    assert result == {
        "operation": operation,
        "status": "confirmation_required",
        "message": (
            "Explicit confirmation is required "
            "before this operation can run."
        ),
    }


@pytest.mark.parametrize(
    (
        "tool_name",
        "dependency_name",
        "tool_arguments",
        "expected_service_arguments",
    ),
    [
        (
            "ingest_rss_articles",
            "ingest_rss_articles_service",
            {},
            {},
        ),
        (
            "process_pending_articles",
            "process_pending_articles_service",
            {
                "limit": 8,
                "include_otx": True,
                "include_cve": False,
            },
            {
                "limit": 8,
                "include_otx": True,
                "include_cve": False,
            },
        ),
        (
            "index_pending_embeddings",
            "index_pending_embeddings_service",
            {
                "limit": 15,
            },
            {
                "limit": 15,
            },
        ),
        (
            "synchronize_mitre_intelligence",
            (
                "synchronize_mitre_"
                "intelligence_service"
            ),
            {
                "domains": [
                    "mobile-attack",
                ],
            },
            {
                "domains": [
                    "mobile-attack",
                ],
            },
        ),
        (
            "synchronize_github_intelligence",
            (
                "synchronize_github_"
                "intelligence_service"
            ),
            {},
            {},
        ),
    ],
)
def test_mutating_tools_execute_after_confirmation(
    monkeypatch,
    tool_name,
    dependency_name,
    tool_arguments,
    expected_service_arguments,
):
    calls = []

    expected_result = {
        "operation": tool_name,
        "status": "completed",
    }

    def fake_service(
        *arguments,
        **keyword_arguments,
    ):
        calls.append({
            "arguments": arguments,
            "keyword_arguments": (
                keyword_arguments
            ),
        })

        return expected_result

    monkeypatch.setattr(
        service,
        dependency_name,
        fake_service,
    )

    tool = getattr(
        service,
        tool_name,
    )

    result = tool(
        confirm=True,
        **tool_arguments,
    )

    assert result is expected_result
    assert calls == [
        {
            "arguments": (),
            "keyword_arguments": (
                expected_service_arguments
            ),
        },
    ]
