from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from api.schemas.articles import (
    PositiveArticleId,
)


ScoreValue = Annotated[
    float,
    Field(ge=0, le=100),
]

NonEmptyText = Annotated[
    str,
    Field(min_length=1),
]

ThreatLevel = Literal[
    "Unknown",
    "Informational",
    "Low",
    "Medium",
    "High",
    "Critical",
]

ConfidenceLevel = Literal[
    "Low",
    "Medium",
    "High",
    "Very High",
]


class ArticleScoringTarget(BaseModel):
    entity_type: Literal["article"]
    article_id: PositiveArticleId
    title: NonEmptyText


class ThreatAssessmentResponse(BaseModel):
    scoring_version: NonEmptyText
    threat_score: ScoreValue
    threat_level: ThreatLevel
    evidence_present: bool
    components: dict[str, dict[str, Any]]
    warnings: list[str]


class ConfidenceAssessmentResponse(BaseModel):
    scoring_version: NonEmptyText
    confidence_score: ScoreValue
    confidence_level: ConfidenceLevel
    components: dict[str, dict[str, Any]]
    warnings: list[str]


class PriorityResponse(BaseModel):
    threat_level: ThreatLevel
    confidence_level: ConfidenceLevel
    priority_code: Literal[
        "P1",
        "P2",
        "P3",
        "P4",
        "P5",
    ]
    priority_label: Literal[
        "Urgent",
        "High",
        "Moderate",
        "Low",
        "Informational",
    ]
    recommended_action: NonEmptyText


class ScoringWarningResponse(BaseModel):
    source: Literal["threat", "confidence"]
    message: NonEmptyText


class ArticleScoringResponse(BaseModel):
    target: ArticleScoringTarget
    otx_selection: dict[str, Any] | None
    scoring_version: NonEmptyText
    threat: ThreatAssessmentResponse
    confidence: ConfidenceAssessmentResponse
    priority: PriorityResponse
    warnings: list[ScoringWarningResponse]
