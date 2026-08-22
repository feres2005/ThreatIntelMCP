from datetime import datetime, timedelta, timezone

from semantic_search.embedding_service import (
    EMBEDDING_MODEL_NAME,
)
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import (
    TfidfVectorizer,
)


DEFAULT_OBSERVATION_DAYS = 30
DEFAULT_RECENT_DAYS = 7
DEFAULT_TOPIC_LIMIT = 10
MAX_ARTICLE_CANDIDATES = 500
MIN_OBSERVATION_DAYS = 2
MAX_OBSERVATION_DAYS = 90
MIN_RECENT_DAYS = 1
MAX_RECENT_DAYS = 30
MIN_TOPIC_LIMIT = 1
MAX_TOPIC_LIMIT = 20
CLUSTER_EPSILON = 0.105
MIN_CLUSTER_SIZE = 3
TOPIC_KEYWORD_COUNT = 5
TREND_THRESHOLD = 0.20
REPRESENTATIVE_ARTICLE_LIMIT = 3

def _is_integer_in_range(
    value,
    minimum,
    maximum,
):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _validate_detection_parameters(
    observation_days,
    recent_days,
    limit,
    reference_time,
):
    if not _is_integer_in_range(
        observation_days,
        MIN_OBSERVATION_DAYS,
        MAX_OBSERVATION_DAYS,
    ):
        raise ValueError(
            "Observation days must be between 2 and 90."
        )

    if not _is_integer_in_range(
        recent_days,
        MIN_RECENT_DAYS,
        MAX_RECENT_DAYS,
    ):
        raise ValueError(
            "Recent days must be between 1 and 30."
        )

    if recent_days >= observation_days:
        raise ValueError(
            "Recent days must be smaller than "
            "observation days."
        )

    if not _is_integer_in_range(
        limit,
        MIN_TOPIC_LIMIT,
        MAX_TOPIC_LIMIT,
    ):
        raise ValueError(
            "Topic limit must be between 1 and 20."
        )

    if (
        reference_time is not None
        and (
            not isinstance(reference_time, datetime)
            or reference_time.tzinfo is None
            or reference_time.utcoffset() is None
        )
    ):
        raise ValueError(
            "Reference time must be timezone-aware."
        )

def _cluster_article_embeddings(articles):
    embedding_matrix = np.asarray(
        [
            article["embedding"]
            for article in articles
        ],
        dtype=float,
    )

    return DBSCAN(
        eps=CLUSTER_EPSILON,
        min_samples=MIN_CLUSTER_SIZE,
        metric="cosine",
    ).fit_predict(embedding_matrix)


def _extract_topic_keywords(articles):
    documents = [
        " ".join(
            value
            for value in (
                article.get("title"),
                article.get("summary"),
            )
            if isinstance(value, str)
            and value.strip()
        )
        for article in articles
    ]

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
    )

    try:
        document_terms = vectorizer.fit_transform(
            documents
        )
    except ValueError:
        return []

    mean_scores = np.asarray(
        document_terms.mean(axis=0)
    ).ravel()
    feature_names = (
        vectorizer.get_feature_names_out()
    )

    ranked_indexes = sorted(
        range(len(feature_names)),
        key=lambda index: (
            -mean_scores[index],
            feature_names[index],
        ),
    )

    return [
        feature_names[index]
        for index in ranked_indexes
        if mean_scores[index] > 0
    ][:TOPIC_KEYWORD_COUNT]


def _calculate_topic_trend(
    articles,
    generated_at,
    recent_days,
    total_recent_article_count,
    total_previous_article_count,
):
    recent_start = generated_at - timedelta(
        days=recent_days,
    )

    recent_count = sum(
        article["published"] >= recent_start
        for article in articles
    )
    previous_count = len(articles) - recent_count

    recent_share = (
        recent_count / total_recent_article_count
        if total_recent_article_count
        else 0.0
    )
    previous_share = (
        previous_count
        / total_previous_article_count
        if total_previous_article_count
        else 0.0
    )

    comparison_scale = max(
        recent_share,
        previous_share,
    )

    if comparison_scale == 0:
        trend_score = 0.0
    else:
        trend_score = (
            recent_share - previous_share
        ) / comparison_scale

    trend_score = round(
        max(-1.0, min(1.0, trend_score)),
        4,
    )

    if trend_score >= TREND_THRESHOLD:
        trend = "rising"
    elif trend_score <= -TREND_THRESHOLD:
        trend = "declining"
    else:
        trend = "stable"

    return {
        "recent_article_count": recent_count,
        "previous_article_count": previous_count,
        "recent_share": round(
            recent_share,
            4,
        ),
        "previous_share": round(
            previous_share,
            4,
        ),
        "trend": trend,
        "trend_score": trend_score,
    }
def _sorted_unique_strings(values):
    unique_values = {}

    for value in values:
        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            continue

        normalized_value = value.strip()
        unique_values.setdefault(
            normalized_value.casefold(),
            normalized_value,
        )

    return sorted(
        unique_values.values(),
        key=str.casefold,
    )


def _collect_list_values(
    articles,
    field_name,
):
    return _sorted_unique_strings(
        value
        for article in articles
        for value in (
            article.get(field_name)
            if isinstance(
                article.get(field_name),
                list,
            )
            else []
        )
    )


def _select_representative_articles(articles):
    embedding_matrix = np.asarray(
        [
            article["embedding"]
            for article in articles
        ],
        dtype=float,
    )
    centroid = embedding_matrix.mean(axis=0)
    centroid_norm = np.linalg.norm(centroid)

    candidates = []

    for article, embedding in zip(
        articles,
        embedding_matrix,
    ):
        embedding_norm = np.linalg.norm(
            embedding
        )

        if (
            centroid_norm == 0
            or embedding_norm == 0
        ):
            similarity = 0.0
        else:
            similarity = float(
                np.dot(embedding, centroid)
                / (embedding_norm * centroid_norm)
            )

        similarity = round(
            max(-1.0, min(1.0, similarity)),
            4,
        )

        candidates.append({
            "article_id": article["article_id"],
            "title": article["title"],
            "link": article["link"],
            "source": article["source"],
            "published": article["published"],
            "similarity_to_centroid": similarity,
        })

    candidates.sort(
        key=lambda article: (
            -article["similarity_to_centroid"],
            article["article_id"],
        )
    )

    return candidates[
        :REPRESENTATIVE_ARTICLE_LIMIT
    ]


def _build_topic(
    articles,
    generated_at,
    recent_days,
    total_recent_article_count,
    total_previous_article_count,
):
    keywords = _extract_topic_keywords(
        articles
    )
    trend = _calculate_topic_trend(
        articles=articles,
        generated_at=generated_at,
        recent_days=recent_days,
        total_recent_article_count=(
            total_recent_article_count
        ),
        total_previous_article_count=(
            total_previous_article_count
        ),
    )

    return {
        "label": (
            " / ".join(keywords[:3])
            if keywords
            else "Unclassified topic"
        ),
        "keywords": keywords,
        "article_count": len(articles),

        "sources": _sorted_unique_strings(
            article.get("source")
            for article in articles
        ),
        "classifications": _collect_list_values(
            articles,
            "classification",
        ),
        "severities": _sorted_unique_strings(
            article.get("severity")
            for article in articles
        ),
        "cves": _collect_list_values(
            articles,
            "cves",
        ),
        "malware": _collect_list_values(
            articles,
            "malware",
        ),
        "mitre_techniques": _collect_list_values(
            articles,
            "mitre_techniques",
        ),
        "apt_groups": _collect_list_values(
            articles,
            "apt_groups",
        ),
        "targeted_sectors": _collect_list_values(
            articles,
            "targeted_sectors",
        ),
        "affected_technologies": (
            _collect_list_values(
                articles,
                "affected_technologies",
            )
        ),
        "representative_articles": (
            _select_representative_articles(
                articles
            )
        ),
        **trend,
    }

def get_topic_modeling_articles(**kwargs):
    from database.embedding_repository import (
        get_topic_modeling_articles as repository_function,
    )

    return repository_function(**kwargs)


def detect_emerging_topics(
    observation_days=DEFAULT_OBSERVATION_DAYS,
    recent_days=DEFAULT_RECENT_DAYS,
    limit=DEFAULT_TOPIC_LIMIT,
    reference_time=None,
):

    _validate_detection_parameters(
        observation_days,
        recent_days,
        limit,
        reference_time,
    )
    generated_at = (
        reference_time
        if reference_time is not None
        else datetime.now(timezone.utc)
    )

    published_after = generated_at - timedelta(
        days=observation_days,
    )

    articles = get_topic_modeling_articles(
        published_after=published_after,
        embedding_model=EMBEDDING_MODEL_NAME,
        limit=MAX_ARTICLE_CANDIDATES,
    )

    if not articles:
        return {
            "generated_at": generated_at,
            "observation_days": observation_days,
            "recent_days": recent_days,
            "limit": limit,
            "considered_article_count": 0,
            "clustered_article_count": 0,
            "noise_article_count": 0,
            "topics": [],
        }

    cluster_labels = _cluster_article_embeddings(
        articles
    )
    clusters = {}

    for article, cluster_label in zip(
        articles,
        cluster_labels,
    ):
        if cluster_label == -1:
            continue

        clusters.setdefault(
            int(cluster_label),
            [],
        ).append(article)
    recent_start = generated_at - timedelta(
        days=recent_days,
    )
    total_recent_article_count = sum(
        article["published"] >= recent_start
        for article in articles
    )
    total_previous_article_count = (
        len(articles)
        - total_recent_article_count
    )

    topics = [
        _build_topic(
            articles=cluster_articles,
            generated_at=generated_at,
            recent_days=recent_days,
            total_recent_article_count=(
                total_recent_article_count
            ),
            total_previous_article_count=(
                total_previous_article_count
            ),
        )
        for cluster_articles in clusters.values()
    ]
    topics.sort(
        key=lambda topic: (
            topic["trend_score"],
            topic["recent_article_count"],
            topic["article_count"],
            topic["label"],
        ),
        reverse=True,
    )
    topics = topics[:limit]

    clustered_article_count = sum(
        len(cluster_articles)
        for cluster_articles in clusters.values()
    )

    return {
        "generated_at": generated_at,
        "observation_days": observation_days,
        "recent_days": recent_days,
        "limit": limit,
        "considered_article_count": len(articles),
        "clustered_article_count": (
            clustered_article_count
        ),
        "noise_article_count": (
            len(articles)
            - clustered_article_count
        ),
        "topics": topics,
    }
