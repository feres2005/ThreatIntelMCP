from datetime import datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)

from api.schemas.articles import (
    PositiveArticleId,
)


SemanticSearchQuery = Annotated[
    str,
    Field(
        min_length=1,
        max_length=500,
    ),
]

SemanticSearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=50,
    ),
]

SimilarityScore = Annotated[
    float,
    Field(
        ge=-1.0,
        le=1.0,
    ),
]

NonNegativeResultCount = Annotated[
    int,
    Field(ge=0),
]


class SemanticArticleSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    article_id: PositiveArticleId
    title: str
    link: HttpUrl
    source: str | None
    published: datetime | None
    summary: str | None
    analysis_available: bool
    similarity: SimilarityScore


class SemanticArticleSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    search_query: SemanticSearchQuery
    limit: SemanticSearchLimit
    returned_count: NonNegativeResultCount
    results: list[SemanticArticleSearchResult]