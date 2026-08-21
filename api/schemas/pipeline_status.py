from typing import Annotated, Literal

from pydantic import BaseModel, Field


NonNegativeInt = Annotated[
    int,
    Field(ge=0),
]

Percentage = Annotated[
    float,
    Field(ge=0, le=100),
]


class PipelineWorkPending(BaseModel):
    article_processing: NonNegativeInt
    embedding_indexing: NonNegativeInt


class PipelineCoverage(BaseModel):
    processing_percent: Percentage
    analysis_percent: Percentage
    embedding_percent: Percentage

class PipelineCounts(BaseModel):
    total_articles: NonNegativeInt
    processed_articles: NonNegativeInt
    pending_articles: NonNegativeInt
    analyzed_articles: NonNegativeInt
    processed_without_analysis: NonNegativeInt
    pending_with_analysis: NonNegativeInt

    typed_ioc_rows: NonNegativeInt
    articles_with_typed_iocs: NonNegativeInt

    article_embeddings: NonNegativeInt
    articles_missing_embeddings: NonNegativeInt

    enriched_cves: NonNegativeInt
    cached_otx_indicators: NonNegativeInt
    mitre_techniques: NonNegativeInt
    github_advisories: NonNegativeInt

class PipelineStatusResponse(BaseModel):
    operation: Literal["get_pipeline_status"]
    health_status: Literal[
        "healthy",
        "attention_required",
    ]
    work_pending: PipelineWorkPending
    coverage: PipelineCoverage
    counts: PipelineCounts
    warnings: list[str]