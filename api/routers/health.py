from fastapi import APIRouter, Request

from api.schemas.health import HealthResponse


router = APIRouter(
    tags=["Health"],
)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Check REST API availability",
)
def get_health(
    request: Request,
) -> HealthResponse:
    return HealthResponse(
        status="healthy",
        service=request.app.title,
        version=request.app.version,
    )