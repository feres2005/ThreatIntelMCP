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
    GithubAdvisoryEcosystem,
    GithubAdvisorySearchResponse,
    GithubAdvisorySeverity,
    GithubAdvisorySupportingArticlesResponse,
)
from database.github_advisory_repository import (
    get_github_advisory_details,
    get_github_advisory_supporting_articles,
    search_github_advisories,
)

router = APIRouter(
    prefix="/api/v1/github",
    tags=["GitHub Advisories"],
)
def _normalize_ghsa_id(ghsa_id):
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

    return (
        "GHSA-"
        + cleaned_ghsa_id[5:].lower()
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
    ecosystem: Annotated[
        GithubAdvisoryEcosystem | None,
        Query(
            description=(
                "Optional affected package "
                "ecosystem filter."
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
        ecosystem=ecosystem,
    )
    return {
        "keyword": normalized_keyword,
        "limit": limit,
        "offset": offset,
        "severity": severity,
        "ecosystem": ecosystem,
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
    normalized_ghsa_id = (
        _normalize_ghsa_id(ghsa_id)
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


@router.get(
    "/advisories/{ghsa_id}/articles",
    response_model=(
        GithubAdvisorySupportingArticlesResponse
    ),
    summary=(
        "Get articles supporting a GitHub "
        "advisory"
    ),
)
def get_github_advisory_articles(
    ghsa_id: Annotated[
        str,
        Path(
            min_length=19,
            max_length=19,
        ),
    ],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=50,
        ),
    ] = 20,
):
    normalized_ghsa_id = (
        _normalize_ghsa_id(ghsa_id)
    )

    try:
        result = (
            get_github_advisory_supporting_articles(
                normalized_ghsa_id,
                limit=limit,
            )
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
                "GitHub advisory "
                f"{normalized_ghsa_id} "
                "was not found."
            ),
        )

    return result