from fastapi import FastAPI
from api.routers.health import (
    router as health_router,
)
from api.routers.pipeline_status import (
    router as pipeline_status_router,
)
from api.routers.articles import (
    router as articles_router,
)
from api.routers.indicators import (
    router as indicators_router,
)
from api.routers import (
    articles,
    cves,
    github_advisories,
    health,
    indicators,
    mitre,
    pipeline_status,
    search,
    topics,
)

import logging

from fastapi import (
    FastAPI,
    Request,
    status,
)
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


async def handle_unexpected_error(
    request: Request,
    error: Exception,
):
    logger.error(
        "Unhandled REST API error for %s %s",
        request.method,
        request.url.path,
        exc_info=(
            type(error),
            error,
            error.__traceback__,
        ),
    )

    return JSONResponse(
        status_code=(
            status.HTTP_500_INTERNAL_SERVER_ERROR
        ),
        content={
            "detail": "Internal server error."
        },
    )

def create_app() -> FastAPI:
    application = FastAPI(
        title="ThreatIntelMCP REST API",
        description=(
            "REST interface for the "
            "ThreatIntelMCP platform."
        ),
        version="1.0.0",
    )
    application.include_router(
        health_router,
    )
    application.include_router(
        pipeline_status_router,
    )
    application.include_router(
        articles_router,
    )
    application.include_router(
        indicators_router,
    )
    application.include_router(
        search.router
    )
    application.include_router(
        topics.router
    )
    application.include_router(
        cves.router
    )
    application.include_router(
        mitre.router
    )
    application.include_router(
        github_advisories.router
    )
    application.add_exception_handler(
        Exception,
        handle_unexpected_error,
    )

    return application


app = create_app()
