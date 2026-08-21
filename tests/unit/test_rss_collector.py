from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import collectors.rss_collector as service


pytestmark = pytest.mark.unit


def test_publication_date_prefers_published_value():
    entry = {
        "published_parsed": (
            2026,
            8,
            21,
            10,
            30,
            45,
            4,
            233,
            0,
        ),
        "updated_parsed": (
            2026,
            8,
            22,
            11,
            45,
            30,
            5,
            234,
            0,
        ),
    }

    result = (
        service.parse_entry_publication_date(
            entry
        )
    )

    assert result == datetime(
        2026,
        8,
        21,
        10,
        30,
        45,
        tzinfo=timezone.utc,
    )


def test_publication_date_falls_back_to_updated():
    entry = {
        "published_parsed": None,
        "updated_parsed": (
            2026,
            8,
            22,
            11,
            45,
            30,
            5,
            234,
            0,
        ),
    }

    result = (
        service.parse_entry_publication_date(
            entry
        )
    )

    assert result == datetime(
        2026,
        8,
        22,
        11,
        45,
        30,
        tzinfo=timezone.utc,
    )


def test_publication_date_returns_none_when_missing():
    assert (
        service.parse_entry_publication_date(
            {}
        )
        is None
    )


def test_collect_articles_handles_empty_feed_configuration(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "RSS_FEEDS",
        {},
    )

    def unexpected_parse(*args, **kwargs):
        raise AssertionError(
            "No feed should be parsed."
        )

    monkeypatch.setattr(
        service.feedparser,
        "parse",
        unexpected_parse,
    )

    assert service.collect_articles() == []


def test_collect_articles_normalizes_multiple_feeds(
    monkeypatch,
):
    feeds = {
        "https://feed.example/one": (
            "source_one"
        ),
        "https://feed.example/two": (
            "source_two"
        ),
        "https://feed.example/empty": (
            "empty_source"
        ),
    }

    parsed_feeds = {
        "https://feed.example/one": (
            SimpleNamespace(
                entries=[
                    {
                        "title": "Article one",
                        "link": (
                            "https://example.com/one"
                        ),
                        "published_parsed": (
                            2026,
                            8,
                            20,
                            8,
                            15,
                            0,
                            3,
                            232,
                            0,
                        ),
                        "summary": (
                            "First controlled summary."
                        ),
                    },
                ],
            )
        ),
        "https://feed.example/two": (
            SimpleNamespace(
                entries=[
                    {
                        "title": "Article two",
                        "link": (
                            "https://example.com/two"
                        ),
                        "updated_parsed": (
                            2026,
                            8,
                            21,
                            9,
                            20,
                            0,
                            4,
                            233,
                            0,
                        ),
                    },
                    {},
                ],
            )
        ),
        "https://feed.example/empty": (
            SimpleNamespace(
                entries=[],
            )
        ),
    }

    calls = []

    def fake_parse(feed_url):
        calls.append(feed_url)
        return parsed_feeds[feed_url]

    monkeypatch.setattr(
        service,
        "RSS_FEEDS",
        feeds,
    )
    monkeypatch.setattr(
        service.feedparser,
        "parse",
        fake_parse,
    )

    result = service.collect_articles()

    assert calls == list(feeds)

    assert result == [
        {
            "title": "Article one",
            "link": "https://example.com/one",
            "published": datetime(
                2026,
                8,
                20,
                8,
                15,
                0,
                tzinfo=timezone.utc,
            ),
            "summary": (
                "First controlled summary."
            ),
            "source": "source_one",
        },
        {
            "title": "Article two",
            "link": "https://example.com/two",
            "published": datetime(
                2026,
                8,
                21,
                9,
                20,
                0,
                tzinfo=timezone.utc,
            ),
            "summary": "",
            "source": "source_two",
        },
        {
            "title": "",
            "link": "",
            "published": None,
            "summary": "",
            "source": "source_two",
        },
    ]
