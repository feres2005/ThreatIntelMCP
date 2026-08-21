from fastapi import APIRouter

from api.schemas.pipeline_status import (
    PipelineStatusResponse,
)
from pipeline.automation_service import (
    get_pipeline_status as get_pipeline_status_service,
)


router = APIRouter(
    prefix="/api/v1/pipeline",
    tags=["Pipeline"],
)


@router.get(
    "/status",
    response_model=PipelineStatusResponse,
    summary="Get pipeline operational status",
)
def read_pipeline_status() -> dict:
    return get_pipeline_status_service()