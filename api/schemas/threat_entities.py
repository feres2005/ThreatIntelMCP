from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)

from api.schemas.articles import (
    ArticleSeverity,
    ConfidenceScore,
    PositiveArticleId,
)


ThreatEntityType = Literal[
    "malware",
    "apt_group",
    "targeted_sector",
    "affected_technology",
]

EntityKeyword = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
    ),
]

EntityValue = Annotated[
    str,
    Field(
        min_length=1,
        max_length=500,
    ),
]

EntitySearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=50,
    ),
]

EntitySearchOffset = Annotated[
    int,
    Field(ge=0),
]

NonNegativeCount = Annotated[
    int,
    Field(ge=0),
]


class ThreatEntitySearchItemResponse(
    BaseModel
):
    model_config = ConfigDict(extra="forbid")

    value: EntityValue
    supporting_article_count: NonNegativeCount
    latest_seen: datetime | None


class ThreatEntitySearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: ThreatEntityType
    keyword: EntityKeyword
    limit: EntitySearchLimit
    offset: EntitySearchOffset
    returned_count: NonNegativeCount
    results: list[
        ThreatEntitySearchItemResponse
    ]


class ThreatEntityArticleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    article_id: PositiveArticleId
    title: str
    link: HttpUrl
    source: str | None
    published: datetime | None
    summary: str | None
    severity: ArticleSeverity | None
    confidence_score: ConfidenceScore | None
    cves: list[str]
    malware: list[str]
    mitre_techniques: list[str]
    apt_groups: list[str]
    targeted_sectors: list[str]
    affected_technologies: list[str]


class ThreatEntityEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: ThreatEntityType
    value: EntityValue
    limit: EntitySearchLimit
    supporting_article_count: NonNegativeCount
    returned_count: NonNegativeCount
    articles: list[
        ThreatEntityArticleResponse
    ]