import asyncio
from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    status,
)

from api.schemas.cves import (
    CveDetailResponse,
    CveSearchResponse,
)
from database.cve_repository import (
    search_cves,
)
from enrichment.cve_lookup_service import (
    lookup_cve,
)


router = APIRouter(
    prefix="/api/v1/cves",
    tags=["CVEs"],
)


@router.get(
    "",
    response_model=CveSearchResponse,
    summary="Search cached CVE intelligence",
)
def search_cve_intelligence(
    keyword: Annotated[
        str,
        Query(
            min_length=1,
            max_length=200,
            pattern=r"\S",
            description=(
                "CVE identifier, description, "
                "or severity keyword."
            ),
        ),
    ],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=50,
        ),
    ] = 10,
    offset: Annotated[
        int,
        Query(ge=0),
    ] = 0,
):
    normalized_keyword = keyword.strip()

    results = search_cves(
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
    "/{cve_id}",
    response_model=CveDetailResponse,
    summary="Get CVE enrichment details",
)
async def get_cve_intelligence(
    cve_id: Annotated[
        str,
        Path(
            min_length=13,
            max_length=40,
            description=(
                "CVE identifier such as "
                "CVE-2026-46242."
            ),
        ),
    ],
):
    try:
        result = await asyncio.to_thread(
            lookup_cve,
            cve_id,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(error),
        ) from error

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"CVE {cve_id.strip().upper()} "
                "was not found."
            ),
        )

    return result