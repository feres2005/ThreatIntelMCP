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
    ScoringWarningResponse,
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


class VirusTotalCommunityVotesResponse(
    BaseModel
):
    harmless: NonNegativeInt = 0
    malicious: NonNegativeInt = 0


class VirusTotalDetectionResponse(BaseModel):
    engine_name: str
    category: Literal[
        "malicious",
        "suspicious",
    ]
    result: str | None
    method: str | None


class VirusTotalEnrichmentResponse(BaseModel):
    indicator: IndicatorValue
    indicator_type: IndicatorType
    report_available: bool
    resource_type: Literal[
        "file",
        "ip_address",
        "domain",
        "url",
    ] | None
    resource_id: str | None
    malicious_count: NonNegativeInt
    suspicious_count: NonNegativeInt
    harmless_count: NonNegativeInt
    undetected_count: NonNegativeInt
    timeout_count: NonNegativeInt
    failure_count: NonNegativeInt
    type_unsupported_count: NonNegativeInt
    confirmed_timeout_count: NonNegativeInt
    total_engine_count: NonNegativeInt
    total_result_count: NonNegativeInt
    reputation: int | None
    community_votes: (
        VirusTotalCommunityVotesResponse
    )
    detections: list[
        VirusTotalDetectionResponse
    ]
    categories: list[str]
    tags: list[str]
    names: list[str]
    meaningful_name: str | None
    file_type: str | None
    country: str | None
    asn: int | None
    as_owner: str | None
    last_analysis_date: datetime | None
    permalink: HttpUrl | None
    last_checked: datetime
    source: Literal["virustotal"]
    cache_status: Literal[
        "fresh",
        "refreshed",
        "stale_fallback",
    ]
    is_stale: bool


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
    virustotal_enrichment: (
        VirusTotalEnrichmentResponse | None
    )

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
    warnings: list[ScoringWarningResponse]