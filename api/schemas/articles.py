from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl


PositiveArticleId = Annotated[
    int,
    Field(gt=0),
]

ConfidenceScore = Annotated[
    float,
    Field(ge=0, le=1),
]

ArticleSeverity = Literal[
    "Critical",
    "High",
    "Medium",
    "Low",
    "None",
]

ArticleSearchLimit = Annotated[
    int,
    Field(ge=1, le=50),
]

ArticleSearchOffset = Annotated[
    int,
    Field(ge=0),
]

ReturnedArticleCount = Annotated[
    int,
    Field(ge=0),
]


class ArticleSearchItemResponse(BaseModel):
    article_id: PositiveArticleId
    title: str
    summary: str | None
    severity: ArticleSeverity | None
    confidence_score: ConfidenceScore | None
    cves: list[str]
    malware: list[str]
    mitre_techniques: list[str]


class ArticleSearchResponse(BaseModel):
    keyword: str
    limit: ArticleSearchLimit
    offset: ArticleSearchOffset
    returned_count: ReturnedArticleCount
    results: list[ArticleSearchItemResponse]

class ArticleDetailResponse(BaseModel):
    article_id: PositiveArticleId
    title: str
    link: HttpUrl
    published: datetime | None
    summary: str | None
    classification: list[str]
    severity: ArticleSeverity | None
    confidence_score: ConfidenceScore | None
    iocs: list[str]
    cves: list[str]
    malware: list[str]
    mitre_techniques: list[str]
    apt_groups: list[str]
    targeted_sectors: list[str]
    affected_technologies: list[str]