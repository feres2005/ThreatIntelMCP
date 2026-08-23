from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    status,
)

from api.schemas.search import (
    SemanticArticleSearchResponse,
)
from semantic_search.subprocess_service import (
    run_semantic_search_worker,
)


router = APIRouter(
    prefix="/api/v1/search",
    tags=["Search"],
)



@router.get(
    "/articles/semantic",
    response_model=SemanticArticleSearchResponse,
    summary="Search articles by semantic meaning",
)
async def semantic_search_articles(
    search_query: Annotated[
        str,
        Query(
            min_length=1,
            max_length=500,
            pattern=r"\S",
            description=(
                "Natural-language description "
                "of a threat or security topic."
            ),
        ),
    ],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=50,
            description=(
                "Maximum number of ranked "
                "articles to return."
            ),
        ),
    ] = 10,
):
    normalized_query = search_query.strip()

    try:
        results = await run_semantic_search_worker(
            normalized_query,
            limit,
        )
    except RuntimeError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Semantic search is temporarily "
                "unavailable."
            ),
        ) from error

    return {
        "search_query": normalized_query,
        "limit": limit,
        "returned_count": len(results),
        "results": results,
    }