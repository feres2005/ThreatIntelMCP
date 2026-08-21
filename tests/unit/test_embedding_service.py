import sys
from types import SimpleNamespace

import pytest

import semantic_search.embedding_service as service


pytestmark = pytest.mark.unit


def test_embedding_model_loads_locally_and_is_cached(
    monkeypatch,
):
    calls = []
    controlled_model = object()

    def fake_sentence_transformer(
        model_name,
        *,
        local_files_only,
    ):
        calls.append({
            "model_name": model_name,
            "local_files_only": (
                local_files_only
            ),
        })

        return controlled_model

    controlled_module = SimpleNamespace(
        SentenceTransformer=(
            fake_sentence_transformer
        ),
    )

    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        controlled_module,
    )

    service.get_embedding_model.cache_clear()

    try:
        first = service.get_embedding_model()
        second = service.get_embedding_model()
    finally:
        service.get_embedding_model.cache_clear()

    assert first is controlled_model
    assert second is controlled_model

    assert calls == [
        {
            "model_name": (
                service.EMBEDDING_MODEL_NAME
            ),
            "local_files_only": True,
        },
    ]


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "   ",
        123,
    ],
)
def test_generate_embedding_rejects_invalid_text(
    text,
):
    with pytest.raises(ValueError) as error_info:
        service.generate_embedding(
            text,
            "query",
        )

    assert str(error_info.value) == (
        "Text must be a non-empty string."
    )


@pytest.mark.parametrize(
    "text_type",
    [
        None,
        "",
        "document",
        True,
    ],
)
def test_generate_embedding_rejects_invalid_text_type(
    text_type,
):
    with pytest.raises(ValueError) as error_info:
        service.generate_embedding(
            "controlled text",
            text_type,
        )

    assert str(error_info.value) == (
        "text_type must be either 'query' "
        "or 'passage'."
    )


@pytest.mark.parametrize(
    (
        "text",
        "text_type",
        "expected_prefixed_text",
    ),
    [
        (
            "  ransomware campaign  ",
            "query",
            "query: ransomware campaign",
        ),
        (
            "  article summary  ",
            "passage",
            "passage: article summary",
        ),
    ],
)
def test_generate_embedding_encodes_normalized_vector(
    monkeypatch,
    text,
    text_type,
    expected_prefixed_text,
):
    calls = []

    class ControlledEmbedding:
        def tolist(self):
            calls.append("tolist")

            return [
                0.1,
                0.2,
                0.3,
            ]

    class ControlledModel:
        def encode(
            self,
            prefixed_text,
            *,
            normalize_embeddings,
        ):
            calls.append({
                "prefixed_text": (
                    prefixed_text
                ),
                "normalize_embeddings": (
                    normalize_embeddings
                ),
            })

            return ControlledEmbedding()

    controlled_model = ControlledModel()

    monkeypatch.setattr(
        service,
        "get_embedding_model",
        lambda: controlled_model,
    )

    result = service.generate_embedding(
        text,
        text_type,
    )

    assert result == [
        0.1,
        0.2,
        0.3,
    ]

    assert calls == [
        {
            "prefixed_text": (
                expected_prefixed_text
            ),
            "normalize_embeddings": True,
        },
        "tolist",
    ]
