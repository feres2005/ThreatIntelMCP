from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)

from api.schemas.articles import (
    PositiveArticleId,
)
from api.schemas.scoring import (
    NonEmptyText,
)


ObservationDays = Annotated[
    int,
    Field(ge=2, le=90),
]
RecentDays = Annotated[
    int,
    Field(ge=1, le=30),
]
TopicLimit = Annotated[
    int,
    Field(ge=1, le=20),
]
NonNegativeCount = Annotated[
    int,
    Field(ge=0),
]
TopicArticleCount = Annotated[
    int,
    Field(ge=3),
]
ShareScore = Annotated[
    float,
    Field(ge=0.0, le=1.0),
]
TrendScore = Annotated[
    float,
    Field(ge=-1.0, le=1.0),
]
CentroidSimilarity = Annotated[
    float,
    Field(ge=-1.0, le=1.0),
]
TopicTrend = Literal[
    "rising",
    "stable",
    "declining",
]


class RepresentativeTopicArticle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    article_id: PositiveArticleId
    title: NonEmptyText
    link: HttpUrl
    source: NonEmptyText | None
    published: datetime
    similarity_to_centroid: CentroidSimilarity


class EmergingTopic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: NonEmptyText
    keywords: list[NonEmptyText]
    article_count: TopicArticleCount
    recent_article_count: NonNegativeCount
    previous_article_count: NonNegativeCount
    recent_share: ShareScore
    previous_share: ShareScore
    trend: TopicTrend
    trend_score: TrendScore
    sources: list[NonEmptyText]
    classifications: list[NonEmptyText]
    severities: list[NonEmptyText]
    cves: list[NonEmptyText]
    malware: list[NonEmptyText]
    mitre_techniques: list[NonEmptyText]
    apt_groups: list[NonEmptyText]
    targeted_sectors: list[NonEmptyText]
    affected_technologies: list[NonEmptyText]
    representative_articles: Annotated[
        list[RepresentativeTopicArticle],
        Field(min_length=1, max_length=3),
    ]


class EmergingTopicsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime
    observation_days: ObservationDays
    recent_days: RecentDays
    limit: TopicLimit
    considered_article_count: NonNegativeCount
    clustered_article_count: NonNegativeCount
    noise_article_count: NonNegativeCount
    topics: Annotated[
        list[EmergingTopic],
        Field(max_length=20),
    ]
