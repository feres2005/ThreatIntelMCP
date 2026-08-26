from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    status,
)

from api.schemas.indicators import (
    IndicatorCorrelationResponse,
    IndicatorScoringResponse,
)
from correlation.indicator_correlation_service import (
    correlate_indicator as correlate_indicator_service,
)
from scoring.indicator_scoring_service import (
    score_indicator as score_indicator_service,
)


IndicatorQuery = Annotated[
    str,
    Query(
        min_length=1,
        max_length=4096,
        pattern=r".*\S.*",
        description=(
            "IPv4, IPv6, domain, URL, "
            "MD5, SHA-1, or SHA-256 IOC."
        ),
    ),
]

IncludeOTXQuery = Annotated[
    bool,
    Query(
        description=(
            "Enable OTX enrichment and "
            "local cache updates."
        ),
    ),
]

IncludeVirusTotalQuery = Annotated[
    bool,
    Query(
        description=(
            "Enable read-only VirusTotal "
            "intelligence retrieval and "
            "24-hour local cache updates."
        ),
    ),
]


router = APIRouter(
    prefix="/api/v1/indicators",
    tags=["Indicators"],
)


@router.get(
    "/correlation",
    response_model=IndicatorCorrelationResponse,
    summary="Correlate a threat indicator",
)
def correlate_threat_indicator(
    indicator: IndicatorQuery,
    include_otx: IncludeOTXQuery = False,
    include_virustotal: (
        IncludeVirusTotalQuery
    ) = False,
) -> dict:
    normalized_input = indicator.strip()

    try:
        return correlate_indicator_service(
            normalized_input,
            include_otx=include_otx,
            include_virustotal=(
                include_virustotal
            ),
        )
    except ValueError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(error),
        ) from error


@router.get(
    "/score",
    response_model=IndicatorScoringResponse,
    summary="Score a threat indicator",
)
def score_threat_indicator(
    indicator: IndicatorQuery,
    include_otx: IncludeOTXQuery = False,
    include_virustotal: (
        IncludeVirusTotalQuery
    ) = False,
) -> dict:
    normalized_input = indicator.strip()

    try:
        return score_indicator_service(
            normalized_input,
            include_otx=include_otx,
            include_virustotal=(
                include_virustotal
            ),
        )
    except ValueError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(error),
        ) from error