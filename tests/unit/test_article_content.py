import pytest

from semantic_search.article_content import (
    build_article_passage,
    calculate_content_hash,
    normalize_text,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        [],
        {},
    ],
)
def test_normalize_text_rejects_non_strings(
    value,
):
    assert normalize_text(value) == ""


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "Threat intelligence",
            "Threat intelligence",
        ),
        (
            "  Threat intelligence  ",
            "Threat intelligence",
        ),
        (
            "Threat\nintelligence\treport",
            "Threat intelligence report",
        ),
        (
            "Multiple   internal    spaces",
            "Multiple internal spaces",
        ),
    ],
)
def test_normalize_text_collapses_whitespace(
    value,
    expected,
):
    assert normalize_text(value) == expected


@pytest.mark.parametrize(
    "title",
    [
        None,
        123,
        "",
        "   ",
        "\t\n",
    ],
)
def test_build_article_passage_rejects_empty_titles(
    title,
):
    with pytest.raises(
        ValueError,
        match="Title must be a non-empty string",
    ):
        build_article_passage(title)


def test_build_article_passage_prefers_ai_summary():
    passage = build_article_passage(
        "Threat report",
        rss_summary="RSS summary",
        ai_summary="AI summary",
    )

    assert passage == (
        "Title: Threat report\n"
        "Summary: AI summary"
    )


def test_build_article_passage_falls_back_to_rss_summary():
    passage = build_article_passage(
        "Threat report",
        rss_summary="RSS summary",
        ai_summary="   ",
    )

    assert passage == (
        "Title: Threat report\n"
        "Summary: RSS summary"
    )


def test_build_article_passage_supports_title_only():
    passage = build_article_passage(
        "Threat report",
        rss_summary=None,
        ai_summary=None,
    )

    assert passage == "Title: Threat report"


def test_build_article_passage_normalizes_all_text():
    passage = build_article_passage(
        "  Threat\n report  ",
        rss_summary=" unused summary ",
        ai_summary=(
            "  AI\tanalysis\nwith   evidence "
        ),
    )

    assert passage == (
        "Title: Threat report\n"
        "Summary: AI analysis with evidence"
    )


@pytest.mark.parametrize(
    "content",
    [
        None,
        123,
        "",
        "   ",
        "\n\t",
    ],
)
def test_calculate_content_hash_rejects_empty_content(
    content,
):
    with pytest.raises(
        ValueError,
        match="Content must be a non-empty string",
    ):
        calculate_content_hash(content)


def test_calculate_content_hash_uses_sha256():
    assert calculate_content_hash("abc") == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_calculate_content_hash_changes_with_content():
    first_hash = calculate_content_hash(
        "Title: First article"
    )
    second_hash = calculate_content_hash(
        "Title: Second article"
    )

    assert first_hash != second_hash
    assert first_hash == calculate_content_hash(
        "Title: First article"
    )
