import pytest

import semantic_search.article_embedding_service as service


pytestmark = pytest.mark.unit


def _article(
    *,
    article_id=501,
    existing_content_hash="old-hash",
    existing_embedding_model=None,
):
    return {
        "article_id": article_id,
        "title": "Controlled article",
        "rss_summary": "Controlled RSS summary.",
        "ai_summary": "Controlled AI summary.",
        "existing_content_hash": (
            existing_content_hash
        ),
        "existing_embedding_model": (
            existing_embedding_model
        ),
    }


def _install_embedding_dependencies(
    monkeypatch,
    *,
    generated_hash="new-hash",
    saved=True,
):
    calls = []

    def fake_build(
        title,
        rss_summary,
        ai_summary,
    ):
        calls.append({
            "operation": "build",
            "title": title,
            "rss_summary": rss_summary,
            "ai_summary": ai_summary,
        })

        return "controlled passage"

    def fake_hash(passage):
        calls.append({
            "operation": "hash",
            "passage": passage,
        })

        return generated_hash

    def fake_generate(
        passage,
        input_type,
    ):
        calls.append({
            "operation": "generate",
            "passage": passage,
            "input_type": input_type,
        })

        return [
            0.1,
            0.2,
            0.3,
        ]

    def fake_save(**kwargs):
        calls.append({
            "operation": "save",
            **kwargs,
        })

        return saved

    monkeypatch.setattr(
        service,
        "build_article_passage",
        fake_build,
    )
    monkeypatch.setattr(
        service,
        "calculate_content_hash",
        fake_hash,
    )
    monkeypatch.setattr(
        service,
        "generate_embedding",
        fake_generate,
    )
    monkeypatch.setattr(
        service,
        "save_intelligence_embedding",
        fake_save,
    )

    return calls


def test_index_article_returns_not_found(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_article_for_embedding",
        lambda article_id: None,
    )

    def unexpected_index(article):
        raise AssertionError(
            "Missing article must not be indexed."
        )

    monkeypatch.setattr(
        service,
        "_index_article_data",
        unexpected_index,
    )

    assert service.index_article(
        501
    ) == {
        "article_id": 501,
        "status": "not_found",
    }


def test_index_article_delegates_existing_article(
    monkeypatch,
):
    article = _article(
        article_id=502,
    )
    calls = []

    def fake_get(article_id):
        calls.append(
            (
                "get",
                article_id,
            )
        )
        return article

    def fake_index(received_article):
        calls.append(
            (
                "index",
                received_article,
            )
        )
        return {
            "article_id": 502,
            "status": "updated",
        }

    monkeypatch.setattr(
        service,
        "get_article_for_embedding",
        fake_get,
    )
    monkeypatch.setattr(
        service,
        "_index_article_data",
        fake_index,
    )

    result = service.index_article(502)

    assert result == {
        "article_id": 502,
        "status": "updated",
    }
    assert calls == [
        (
            "get",
            502,
        ),
        (
            "index",
            article,
        ),
    ]


def test_index_article_data_skips_unchanged_content(
    monkeypatch,
):
    calls = (
        _install_embedding_dependencies(
            monkeypatch,
            generated_hash="same-hash",
        )
    )

    article = _article(
        article_id=503,
        existing_content_hash="same-hash",
        existing_embedding_model=(
            service.EMBEDDING_MODEL_NAME
        ),
    )

    result = service._index_article_data(
        article
    )

    assert result == {
        "article_id": 503,
        "status": "unchanged",
    }

    assert [
        call["operation"]
        for call in calls
    ] == [
        "build",
        "hash",
    ]


def test_index_article_data_creates_new_embedding(
    monkeypatch,
):
    calls = (
        _install_embedding_dependencies(
            monkeypatch,
            generated_hash="new-hash",
            saved=True,
        )
    )

    article = _article(
        article_id=504,
        existing_content_hash=None,
        existing_embedding_model=None,
    )

    result = service._index_article_data(
        article
    )

    assert result == {
        "article_id": 504,
        "status": "created",
    }

    assert [
        call["operation"]
        for call in calls
    ] == [
        "build",
        "hash",
        "generate",
        "save",
    ]

    save_call = calls[-1]

    assert save_call == {
        "operation": "save",
        "entity_type": "article",
        "entity_id": 504,
        "embedding": [
            0.1,
            0.2,
            0.3,
        ],
        "embedding_model": (
            service.EMBEDDING_MODEL_NAME
        ),
        "content_hash": "new-hash",
    }


def test_index_article_data_updates_changed_content(
    monkeypatch,
):
    _install_embedding_dependencies(
        monkeypatch,
        generated_hash="new-hash",
        saved=True,
    )

    article = _article(
        article_id=505,
        existing_content_hash="old-hash",
        existing_embedding_model=(
            service.EMBEDDING_MODEL_NAME
        ),
    )

    assert service._index_article_data(
        article
    ) == {
        "article_id": 505,
        "status": "updated",
    }


def test_index_article_data_updates_changed_model(
    monkeypatch,
):
    calls = (
        _install_embedding_dependencies(
            monkeypatch,
            generated_hash="same-hash",
            saved=True,
        )
    )

    article = _article(
        article_id=506,
        existing_content_hash="same-hash",
        existing_embedding_model=(
            "old-embedding-model"
        ),
    )

    result = service._index_article_data(
        article
    )

    assert result == {
        "article_id": 506,
        "status": "updated",
    }

    assert [
        call["operation"]
        for call in calls
    ] == [
        "build",
        "hash",
        "generate",
        "save",
    ]


def test_index_article_data_handles_unsaved_embedding(
    monkeypatch,
):
    _install_embedding_dependencies(
        monkeypatch,
        generated_hash="new-hash",
        saved=False,
    )

    article = _article(
        article_id=507,
        existing_content_hash="old-hash",
        existing_embedding_model=(
            service.EMBEDDING_MODEL_NAME
        ),
    )

    assert service._index_article_data(
        article
    ) == {
        "article_id": 507,
        "status": "unchanged",
    }


def test_index_missing_articles_handles_empty_batch(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_articles_without_embeddings",
        lambda limit: [],
    )

    assert service.index_missing_articles(
        10
    ) == []


def test_index_missing_articles_isolates_failures(
    monkeypatch,
):
    articles = [
        _article(
            article_id=508,
        ),
        _article(
            article_id=509,
        ),
        {
            "title": "Missing identifier",
        },
    ]

    requested_limits = []

    def fake_get(limit):
        requested_limits.append(limit)
        return articles

    def fake_index(article):
        article_id = article.get(
            "article_id"
        )

        if article_id == 508:
            return {
                "article_id": 508,
                "status": "created",
            }

        if article_id == 509:
            raise RuntimeError(
                "Controlled embedding failure"
            )

        raise ValueError(
            "Article identifier is missing"
        )

    monkeypatch.setattr(
        service,
        "get_articles_without_embeddings",
        fake_get,
    )
    monkeypatch.setattr(
        service,
        "_index_article_data",
        fake_index,
    )

    result = service.index_missing_articles(
        3
    )

    assert requested_limits == [
        3,
    ]

    assert result == [
        {
            "article_id": 508,
            "status": "created",
        },
        {
            "article_id": 509,
            "status": "failed",
            "error": (
                "RuntimeError: "
                "Controlled embedding failure"
            ),
        },
        {
            "article_id": None,
            "status": "failed",
            "error": (
                "ValueError: "
                "Article identifier is missing"
            ),
        },
    ]
