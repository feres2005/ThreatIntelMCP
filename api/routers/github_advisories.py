import re
from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    status,
)

from api.schemas.github_advisories import (
    GithubAdvisoryDetailResponse,
    GithubAdvisorySearchResponse,
    GithubAdvisorySeverity,
)
from database.github_advisory_repository import (
    get_github_advisory_details,
    search_github_advisories,
)


router = APIRouter(
    prefix="/api/v1/github",
    tags=["GitHub Advisories"],
)


@router.get(
    "/advisories",
    response_model=GithubAdvisorySearchResponse,
    summary="Search GitHub security advisories",
)
def search_github_advisory_intelligence(
    keyword: Annotated[
        str,
        Query(
            min_length=1,
            max_length=200,
            pattern=r"\S",
            description=(
                "GHSA ID, CVE ID, summary, "
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
    severity: Annotated[
        GithubAdvisorySeverity | None,
        Query(
            description=(
                "Optional GitHub advisory "
                "severity filter."
            ),
        ),
    ] = None,
):
    normalized_keyword = keyword.strip()

    results = search_github_advisories(
        normalized_keyword,
        limit=limit,
        offset=offset,
        severity=severity,
    )

    return {
        "keyword": normalized_keyword,
        "limit": limit,
        "offset": offset,
        "severity": severity,
        "returned_count": len(results),
        "results": results,
    }


@router.get(
    "/advisories/{ghsa_id}",
    response_model=GithubAdvisoryDetailResponse,
    summary="Get GitHub advisory details",
)
def get_github_advisory_intelligence(
    ghsa_id: Annotated[
        str,
        Path(
            min_length=19,
            max_length=19,
            description=(
                "GitHub advisory identifier."
            ),
        ),
    ],
):
    cleaned_ghsa_id = ghsa_id.strip()

    if re.fullmatch(
        (
            r"GHSA-[a-z0-9]{4}-"
            r"[a-z0-9]{4}-[a-z0-9]{4}"
        ),
        cleaned_ghsa_id,
        flags=re.IGNORECASE,
    ) is None:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=(
                "GitHub advisory ID is invalid."
            ),
        )

    normalized_ghsa_id = (
        "GHSA-"
        + cleaned_ghsa_id[5:].lower()
    )

    result = get_github_advisory_details(
        normalized_ghsa_id
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "GitHub advisory "
                f"{normalized_ghsa_id} "
                "was not found."
            ),
        )

    return result