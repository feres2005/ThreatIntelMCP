import re
from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    status,
)

from api.schemas.mitre import (
    MitreDomain,
    MitreSearchResponse,
    MitreTechniqueDetailResponse,
    MitreSupportingArticlesResponse,
)
from database.mitre_repository import (
    get_mitre_supporting_articles,
    get_mitre_technique_details,
    search_mitre_techniques,
)


router = APIRouter(
    prefix="/api/v1/mitre",
    tags=["MITRE ATT&CK"],
)


@router.get(
    "/techniques",
    response_model=MitreSearchResponse,
    summary="Search MITRE ATT&CK techniques",
)
def search_mitre_intelligence(
    keyword: Annotated[
        str,
        Query(
            min_length=1,
            max_length=200,
            pattern=r"\S",
            description=(
                "Technique identifier, name, "
                "description, or platform."
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
    domain: Annotated[
        MitreDomain | None,
        Query(
            description=(
                "Optional ATT&CK dataset "
                "domain."
            ),
        ),
    ] = None,
    include_inactive: Annotated[
        bool,
        Query(
            description=(
                "Include revoked and deprecated "
                "historical techniques."
            ),
        ),
    ] = False,
):
    normalized_keyword = keyword.strip()

    results = search_mitre_techniques(
        normalized_keyword,
        limit=limit,
        offset=offset,
        domain=domain,
        include_inactive=include_inactive,
    )

    return {
        "keyword": normalized_keyword,
        "limit": limit,
        "offset": offset,
        "domain": domain,
        "returned_count": len(results),
        "results": results,
        "include_inactive": include_inactive,
    }

@router.get(
    "/techniques/{technique_id}/articles",
    response_model=(
        MitreSupportingArticlesResponse
    ),
    summary=(
        "Get articles supporting a "
        "MITRE technique"
    ),
)
def get_mitre_article_evidence(
    technique_id: Annotated[
        str,
        Path(
            min_length=1,
            max_length=20,
            description=(
                "Technique ID such as T1566 "
                "or T1566.002."
            ),
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
    try:
        evidence = (
            get_mitre_supporting_articles(
                technique_id,
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

    articles = evidence["articles"]

    return {
        "technique_id": (
            evidence["technique_id"]
        ),
        "limit": limit,
        "supporting_article_count": (
            evidence[
                "supporting_article_count"
            ]
        ),
        "returned_count": len(articles),
        "articles": articles,
    }

@router.get(
    "/techniques/{technique_id}",
    response_model=MitreTechniqueDetailResponse,
    summary="Get MITRE ATT&CK technique details",
)
def get_mitre_intelligence(
    technique_id: Annotated[
        str,
        Path(
            min_length=5,
            max_length=9,
            description=(
                "Technique ID such as T1566 "
                "or T1566.002."
            ),
        ),
    ],
):
    normalized_technique_id = (
        technique_id.strip().upper()
    )

    if re.fullmatch(
        r"T\d{4}(?:\.\d{3})?",
        normalized_technique_id,
    ) is None:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=(
                "MITRE technique ID is invalid."
            ),
        )

    result = get_mitre_technique_details(
        normalized_technique_id
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "MITRE technique "
                f"{normalized_technique_id} "
                "was not found."
            ),
        )

    return result