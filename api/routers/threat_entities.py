from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    status,
)

from api.schemas.threat_entities import (
    ThreatEntityEvidenceResponse,
    ThreatEntitySearchResponse,
    ThreatEntityType,
)
from database.threat_entity_repository import (
    get_threat_entity_evidence,
    search_threat_entity_values,
)


router = APIRouter(
    prefix="/api/v1/entities",
    tags=["Threat Entities"],
)


@router.get(
    "",
    response_model=ThreatEntitySearchResponse,
    summary="Search article-derived entities",
)
def search_threat_entities(
    entity_type: Annotated[
        ThreatEntityType,
        Query(
            description=(
                "Article-derived entity category."
            ),
        ),
    ],
    keyword: Annotated[
        str,
        Query(
            min_length=1,
            max_length=200,
            pattern=r"\S",
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

    try:
        return search_threat_entity_values(
            entity_type,
            normalized_keyword,
            limit=limit,
            offset=offset,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(error),
        ) from error


@router.get(
    "/evidence",
    response_model=ThreatEntityEvidenceResponse,
    summary=(
        "Get articles supporting a threat entity"
    ),
)
def get_threat_entity_article_evidence(
    entity_type: Annotated[
        ThreatEntityType,
        Query(
            description=(
                "Article-derived entity category."
            ),
        ),
    ],
    value: Annotated[
        str,
        Query(
            min_length=1,
            max_length=500,
            pattern=r"\S",
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
    normalized_value = value.strip()

    try:
        return get_threat_entity_evidence(
            entity_type,
            normalized_value,
            limit=limit,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(error),
        ) from error