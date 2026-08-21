import pytest

import semantic_search.search_service as service


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "search_query",
    [
        None,
        "",
        "   ",
        123,
    ],
)
def test_semantic_search_rejects_invalid_query(
    search_query,
):
    with pytest.raises(ValueError) as error_info:
        service.semantic_search_articles(
            search_query
        )

    assert str(error_info.value) == (
        "Search query must be a non-empty string."
    )


@pytest.mark.parametrize(
    "limit",
    [
        None,
        True,
        False,
        0,
        -1,
        51,
        "10",
    ],
)
def test_semantic_search_rejects_invalid_limit(
    limit,
):
    with pytest.raises(ValueError) as error_info:
        service.semantic_search_articles(
            "ransomware",
            limit=limit,
        )

    assert str(error_info.value) == (
        "Limit must be between 1 and 50."
    )


def test_semantic_search_generates_query_embedding(
    monkeypatch,
):
    calls = []

    expected_embedding = [
        0.1,
        0.2,
        0.3,
    ]
    expected_results = [
        {
            "article_id": 601,
            "title": "Controlled result",
            "similarity": 0.91,
        },
    ]

    def fake_generate(
        text,
        input_type,
    ):
        calls.append({
            "operation": "generate",
            "text": text,
            "input_type": input_type,
        })

        return expected_embedding

    def fake_search(**kwargs):
        calls.append({
            "operation": "search",
            **kwargs,
        })

        return expected_results

    monkeypatch.setattr(
        service,
        "generate_embedding",
        fake_generate,
    )
    monkeypatch.setattr(
        service,
        "search_article_embeddings",
        fake_search,
    )

    result = service.semantic_search_articles(
        "  ransomware targeting hospitals  "
    )

    assert result is expected_results

    assert calls == [
        {
            "operation": "generate",
            "text": (
                "  ransomware targeting "
                "hospitals  "
            ),
            "input_type": "query",
        },
        {
            "operation": "search",
            "query_embedding": (
                expected_embedding
            ),
            "embedding_model": (
                service.EMBEDDING_MODEL_NAME
            ),
            "limit": 10,
        },
    ]


@pytest.mark.parametrize(
    "limit",
    [
        1,
        50,
    ],
)
def test_semantic_search_accepts_limit_boundaries(
    monkeypatch,
    limit,
):
    monkeypatch.setattr(
        service,
        "generate_embedding",
        lambda text, input_type: [
            0.25,
        ],
    )

    received = []

    def fake_search(**kwargs):
        received.append(kwargs)
        return []

    monkeypatch.setattr(
        service,
        "search_article_embeddings",
        fake_search,
    )

    result = service.semantic_search_articles(
        "phishing",
        limit=limit,
    )

    assert result == []
    assert received == [
        {
            "query_embedding": [
                0.25,
            ],
            "embedding_model": (
                service.EMBEDDING_MODEL_NAME
            ),
            "limit": limit,
        },
    ]
