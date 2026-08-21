from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    status,
)
from database.article_repository import (
    get_article_details as get_article_details_repository,
    search_articles as search_articles_repository,
)
from api.schemas.articles import (
    ArticleDetailResponse,
    ArticleSearchResponse,
)
from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    status,
)
from api.schemas.investigations import (
    ArticleInvestigationResponse,
)
from correlation.article_investigation_service import (
    get_article_investigation as get_article_investigation_service,
)
from api.schemas.scoring import (
    ArticleScoringResponse,
)
from scoring.article_scoring_service import (
    score_article as score_article_service,
)

router = APIRouter(
    prefix="/api/v1/articles",
    tags=["Articles"],
)


@router.get(
    "",
    response_model=ArticleSearchResponse,
    summary="Search analyzed threat articles",
)
def search_analyzed_articles(
    keyword: Annotated[
        str,
        Query(
            min_length=1,
            max_length=200,
            pattern=r".*\S.*",
            description=(
                "Keyword matched against article "
                "titles and AI summaries."
            ),
        ),
    ],
    limit: Annotated[
        int,
        Query(ge=1, le=50),
    ] = 10,
    offset: Annotated[
        int,
        Query(ge=0),
    ] = 0,
) -> dict:
    normalized_keyword = keyword.strip()

    results = search_articles_repository(
        normalized_keyword,
        limit=limit,
        offset=offset,
    )

    return {
        "keyword": normalized_keyword,
        "limit": limit,
        "offset": offset,
        "returned_count": len(results),
        "results": results,
    }

@router.get(
    "/{article_id}",
    response_model=ArticleDetailResponse,
    summary="Get analyzed article details",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": (
                "Analyzed article not found."
            ),
        },
    },
)
def read_article_details(
    article_id: Annotated[
        int,
        Path(
            gt=0,
            description=(
                "Positive article identifier."
            ),
        ),
    ],
) -> dict:
    article = get_article_details_repository(
        article_id
    )

    if article is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Analyzed article {article_id} "
                "was not found."
            ),
        )

    return article

@router.get(
    "/{article_id}/investigation",
    response_model=ArticleInvestigationResponse,
    summary="Build an article investigation",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": (
                "Article investigation not found."
            ),
        },
    },
)
def investigate_article(
    article_id: Annotated[
        int,
        Path(
            gt=0,
            description=(
                "Positive article identifier."
            ),
        ),
    ],
    include_otx: Annotated[
        bool,
        Query(
            description=(
                "Enable OTX enrichment and "
                "local cache updates."
            ),
        ),
    ] = False,
) -> dict:
    investigation = (
        get_article_investigation_service(
            article_id,
            include_otx=include_otx,
        )
    )

    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Investigation for analyzed "
                f"article {article_id} "
                "was not found."
            ),
        )

    return investigation

@router.get(
    "/{article_id}/score",
    response_model=ArticleScoringResponse,
    summary="Score an analyzed threat article",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": (
                "Article scoring report not found."
            ),
        },
    },
)
def score_analyzed_article(
    article_id: Annotated[
        int,
        Path(
            gt=0,
            description=(
                "Positive article identifier."
            ),
        ),
    ],
    include_otx: Annotated[
        bool,
        Query(
            description=(
                "Enable OTX enrichment and "
                "local cache updates before "
                "scoring."
            ),
        ),
    ] = False,
) -> dict:
    report = score_article_service(
        article_id,
        include_otx=include_otx,
    )

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Scoring report for analyzed "
                f"article {article_id} "
                "was not found."
            ),
        )

    return report