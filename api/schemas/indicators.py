from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, HttpUrl

from api.schemas.articles import (
    ArticleSeverity,
    ConfidenceScore,
    PositiveArticleId,
)
from api.schemas.scoring import (
    ConfidenceAssessmentResponse,
    NonEmptyText,
    PriorityResponse,
    ThreatAssessmentResponse,
)

NonNegativeInt = Annotated[
    int,
    Field(ge=0),
]

IndicatorValue = Annotated[
    str,
    Field(min_length=1, max_length=4096),
]

IndicatorType = Literal[
    "IPv4",
    "IPv6",
    "URL",
    "domain",
    "FileHash-MD5",
    "FileHash-SHA1",
    "FileHash-SHA256",
]


class SupportingArticleResponse(BaseModel):
    article_id: PositiveArticleId
    title: str
    link: HttpUrl
    published: datetime | None
    severity: ArticleSeverity | None
    confidence_score: ConfidenceScore | None


class RelatedEntityEvidenceResponse(BaseModel):
    value: str
    supporting_article_count: NonNegativeInt
    supporting_article_ids: list[PositiveArticleId]


class RelatedEntitiesResponse(BaseModel):
    cves: list[RelatedEntityEvidenceResponse]
    malware: list[RelatedEntityEvidenceResponse]
    mitre_techniques: list[
        RelatedEntityEvidenceResponse
    ]
    apt_groups: list[RelatedEntityEvidenceResponse]
    targeted_sectors: list[
        RelatedEntityEvidenceResponse
    ]
    affected_technologies: list[
        RelatedEntityEvidenceResponse
    ]


class IndicatorCorrelationResponse(BaseModel):
    indicator: IndicatorValue
    indicator_type: IndicatorType
    supporting_article_count: NonNegativeInt
    supporting_article_ids: list[PositiveArticleId]
    supporting_articles: list[
        SupportingArticleResponse
    ]
    related_entities: RelatedEntitiesResponse
    otx_enrichment: dict[str, Any] | None

class IndicatorScoringTarget(BaseModel):
    entity_type: Literal["indicator"]
    indicator: IndicatorValue
    indicator_type: IndicatorType


class IndicatorScoringResponse(BaseModel):
    target: IndicatorScoringTarget
    scoring_version: NonEmptyText
    threat: ThreatAssessmentResponse
    confidence: ConfidenceAssessmentResponse
    priority: PriorityResponse
    warnings: list[str]
