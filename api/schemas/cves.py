from datetime import datetime
from typing import Annotated
from pydantic import (
    AnyUrl,
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

CveId = Annotated[
    str,
    Field(
        pattern=r"^CVE-\d{4}-\d{4,}$",
    ),
]

CvssScore = Annotated[
    float,
    Field(
        ge=0.0,
        le=10.0,
    ),
]

CveSearchKeyword = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
    ),
]

CveSearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=50,
    ),
]

CveSearchOffset = Annotated[
    int,
    Field(ge=0),
]

NonNegativeResultCount = Annotated[
    int,
    Field(ge=0),
]


class CveSearchItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: CveId
    description: str | None
    cvss_score: CvssScore | None
    severity: str | None
    published: datetime | None
    last_modified: datetime | None


class CveSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keyword: CveSearchKeyword
    limit: CveSearchLimit
    offset: CveSearchOffset
    returned_count: NonNegativeResultCount
    results: list[CveSearchItemResponse]

class CveDetailResponse(CveSearchItemResponse):
    reference_links: list[AnyUrl]
    enriched_at: datetime | None

class CveSupportingArticleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    article_id: PositiveArticleId
    title: str
    link: HttpUrl
    source: str
    published: datetime | None
    severity: ArticleSeverity | None
    confidence_score: ConfidenceScore | None


class CveSupportingArticlesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: CveId
    limit: CveSearchLimit
    supporting_article_count: (
        NonNegativeResultCount
    )
    returned_count: NonNegativeResultCount
    articles: list[
        CveSupportingArticleResponse
    ]