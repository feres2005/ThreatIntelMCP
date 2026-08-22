from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    status,
)
from starlette.concurrency import (
    run_in_threadpool,
)

from api.schemas.topics import (
    EmergingTopicsResponse,
)
from topic_modeling.emerging_topic_service import (
    detect_emerging_topics,
)


router = APIRouter(
    prefix="/api/v1/topics",
    tags=["Topics"],
)


@router.get(
    "/emerging",
    response_model=EmergingTopicsResponse,
    summary="Detect emerging threat topics",
)
async def get_emerging_topics(
    observation_days: Annotated[
        int,
        Query(
            ge=2,
            le=90,
            description=(
                "Number of days included in "
                "topic detection."
            ),
        ),
    ] = 30,
    recent_days: Annotated[
        int,
        Query(
            ge=1,
            le=30,
            description=(
                "Recent period compared with "
                "the earlier observation period."
            ),
        ),
    ] = 7,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=20,
            description=(
                "Maximum number of topics "
                "returned."
            ),
        ),
    ] = 10,
):
    if recent_days >= observation_days:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=(
                "Recent days must be smaller "
                "than observation days."
            ),
        )

    try:
        return await run_in_threadpool(
            detect_emerging_topics,
            observation_days=observation_days,
            recent_days=recent_days,
            limit=limit,
        )
    except (RuntimeError, ValueError) as error:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Emerging topic detection is "
                "temporarily unavailable."
            ),
        ) from error
