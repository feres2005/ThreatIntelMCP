from datetime import datetime, timedelta, timezone

import pytest

import topic_modeling.emerging_topic_service as service


pytestmark = pytest.mark.unit


def test_detect_emerging_topics_handles_empty_dataset(
    monkeypatch,
):
    calls = []

    def fake_get_articles(**kwargs):
        calls.append(kwargs)
        return []

    monkeypatch.setattr(
        service,
        "get_topic_modeling_articles",
        fake_get_articles,
    )

    reference_time = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    result = service.detect_emerging_topics(
        reference_time=reference_time,
    )

    assert result == {
        "generated_at": reference_time,
        "observation_days": 30,
        "recent_days": 7,
        "limit": 10,
        "considered_article_count": 0,
        "clustered_article_count": 0,
        "noise_article_count": 0,
        "topics": [],
    }
@pytest.mark.parametrize(
    (
        "arguments",
        "expected_message",
    ),
    [
        (
            {"observation_days": 1},
            "Observation days must be between 2 and 90.",
        ),
        (
            {"observation_days": 91},
            "Observation days must be between 2 and 90.",
        ),
        (
            {"observation_days": True},
            "Observation days must be between 2 and 90.",
        ),
        (
            {"recent_days": 0},
            "Recent days must be between 1 and 30.",
        ),
        (
            {"recent_days": 31},
            "Recent days must be between 1 and 30.",
        ),
        (
            {"recent_days": False},
            "Recent days must be between 1 and 30.",
        ),
        (
            {
                "observation_days": 7,
                "recent_days": 7,
            },
            (
                "Recent days must be smaller than "
                "observation days."
            ),
        ),
        (
            {"limit": 0},
            "Topic limit must be between 1 and 20.",
        ),
        (
            {"limit": 21},
            "Topic limit must be between 1 and 20.",
        ),
        (
            {"limit": True},
            "Topic limit must be between 1 and 20.",
        ),
        (
            {
                "reference_time": datetime(
                    2026,
                    8,
                    22,
                    12,
                    0,
                ),
            },
            "Reference time must be timezone-aware.",
        ),
    ],
)
def test_detect_emerging_topics_rejects_invalid_parameters(
    monkeypatch,
    arguments,
    expected_message,
):
    monkeypatch.setattr(
        service,
        "get_topic_modeling_articles",
        lambda **kwargs: pytest.fail(
            "The repository must not be called."
        ),
    )

    with pytest.raises(ValueError) as error_info:
        service.detect_emerging_topics(**arguments)

    assert str(error_info.value) == expected_message


def _build_topic_article(
    article_id,
    title,
    published,
    embedding,
):
    return {
        "article_id": article_id,
        "title": title,
        "link": (
            f"https://example.com/articles/{article_id}"
        ),
        "source": "controlled_feed",
        "published": published,
        "summary": title,
        "classification": [],
        "severity": None,
        "confidence_score": None,
        "cves": [],
        "malware": [],
        "mitre_techniques": [],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": [],
        "embedding": embedding,

    }


def test_detect_emerging_topics_clusters_rising_topic(
    monkeypatch,
):
    reference_time = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    articles = [
        _build_topic_article(
            801,
            "Ransomware attacks hospitals",
            reference_time - timedelta(days=1),
            [1.0, 0.0, 0.0],
        ),
        _build_topic_article(
            802,
            "Ransomware campaign targets healthcare",
            reference_time - timedelta(days=2),
            [0.99, 0.01, 0.0],
        ),
        _build_topic_article(
            803,
            "Ransomware disrupts hospital systems",
            reference_time - timedelta(days=3),
            [0.98, 0.02, 0.0],
        ),
        _build_topic_article(
            804,
            "Ransomware warning for medical networks",
            reference_time - timedelta(days=15),
            [0.97, 0.03, 0.0],
        ),
        _build_topic_article(
            805,
            "Unrelated phishing email",
            reference_time - timedelta(days=15),
            [0.0, 1.0, 0.0],
        ),
    ]

    monkeypatch.setattr(
        service,
        "get_topic_modeling_articles",
        lambda **kwargs: articles,
    )

    result = service.detect_emerging_topics(
        reference_time=reference_time,
    )

    assert result["considered_article_count"] == 5
    assert result["clustered_article_count"] == 4
    assert result["noise_article_count"] == 1
    assert len(result["topics"]) == 1

    topic = result["topics"][0]

    assert "ransomware" in topic["keywords"]
    assert topic["article_count"] == 4
    assert topic["recent_article_count"] == 3
    assert topic["previous_article_count"] == 1
    assert topic["trend"] == "rising"
    assert topic["trend_score"] > 0
def test_detect_emerging_topics_aggregates_evidence(
    monkeypatch,
):
    reference_time = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    articles = [
        _build_topic_article(
            901,
            "Ransomware attacks hospitals",
            reference_time - timedelta(days=1),
            [1.0, 0.0, 0.0],
        ),
        _build_topic_article(
            902,
            "Ransomware targets healthcare",
            reference_time - timedelta(days=2),
            [0.99, 0.01, 0.0],
        ),
        _build_topic_article(
            903,
            "Ransomware disrupts medical systems",
            reference_time - timedelta(days=3),
            [0.98, 0.02, 0.0],
        ),
        _build_topic_article(
            904,
            "Ransomware warning for hospitals",
            reference_time - timedelta(days=15),
            [0.97, 0.03, 0.0],
        ),
    ]

    articles[0].update({
        "source": "feed_b",
        "classification": ["ransomware"],
        "severity": "High",
        "cves": ["CVE-2026-1000"],
        "malware": ["ExampleLock"],
        "mitre_techniques": ["T1486"],
        "apt_groups": ["Example Group"],
        "targeted_sectors": ["Healthcare"],
        "affected_technologies": ["Windows"],
    })
    articles[1].update({
        "source": "feed_a",
        "classification": [
            "ransomware",
            "vulnerability",
        ],
        "severity": "Critical",
        "cves": [
            "CVE-2026-1000",
            "CVE-2026-2000",
        ],
        "malware": ["ExampleLock"],
        "targeted_sectors": ["Healthcare"],
    })
    articles[2]["source"] = "feed_c"
    articles[3]["source"] = "feed_a"

    monkeypatch.setattr(
        service,
        "get_topic_modeling_articles",
        lambda **kwargs: articles,
    )

    result = service.detect_emerging_topics(
        reference_time=reference_time,
    )
    topic = result["topics"][0]

    assert topic["sources"] == [
        "feed_a",
        "feed_b",
        "feed_c",
    ]
    assert topic["classifications"] == [
        "ransomware",
        "vulnerability",
    ]
    assert topic["severities"] == [
        "Critical",
        "High",
    ]
    assert topic["cves"] == [
        "CVE-2026-1000",
        "CVE-2026-2000",
    ]
    assert topic["malware"] == ["ExampleLock"]
    assert topic["mitre_techniques"] == ["T1486"]
    assert topic["apt_groups"] == ["Example Group"]
    assert topic["targeted_sectors"] == [
        "Healthcare",
    ]
    assert topic["affected_technologies"] == [
        "Windows",
    ]

    representative_articles = topic[
        "representative_articles"
    ]

    assert len(representative_articles) == 3

    representative_ids = {
        article["article_id"]
        for article in representative_articles
    }

    assert 904 not in representative_ids
    assert representative_ids == {
        901,
        902,
        903,
    }

    assert all(
        0 <= article["similarity_to_centroid"] <= 1
        for article in representative_articles
    )

def test_topic_trend_uses_relative_article_share(
    monkeypatch,
):
    reference_time = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    articles = [
        _build_topic_article(
            1001,
            "Repeated cloud security topic",
            reference_time - timedelta(days=1),
            [1.0, 0.0, 0.0],
        ),
        _build_topic_article(
            1002,
            "Repeated cloud security issue",
            reference_time - timedelta(days=2),
            [0.99, 0.01, 0.0],
        ),
        _build_topic_article(
            1003,
            "Repeated cloud security report",
            reference_time - timedelta(days=10),
            [0.98, 0.02, 0.0],
        ),
        _build_topic_article(
            1004,
            "Repeated cloud security warning",
            reference_time - timedelta(days=20),
            [0.97, 0.03, 0.0],
        ),
    ]

    monkeypatch.setattr(
        service,
        "get_topic_modeling_articles",
        lambda **kwargs: articles,
    )

    result = service.detect_emerging_topics(
        reference_time=reference_time,
    )
    topic = result["topics"][0]

    assert topic["recent_article_count"] == 2
    assert topic["previous_article_count"] == 2
    assert topic["recent_share"] == 1.0
    assert topic["previous_share"] == 1.0
    assert topic["trend"] == "stable"
    assert topic["trend_score"] == 0.0
