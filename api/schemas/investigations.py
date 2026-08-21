from typing import Annotated, Any

from pydantic import BaseModel, Field

from api.schemas.articles import (
    ArticleDetailResponse,
)


NonEmptyText = Annotated[
    str,
    Field(min_length=1),
]

CVEIdentifier = Annotated[
    str,
    Field(
        pattern=r"^CVE-\d{4}-\d{4,}$",
    ),
]

MitreTechniqueIdentifier = Annotated[
    str,
    Field(
        pattern=r"^T\d{4}(?:\.\d{3})?$",
    ),
]


class TypedIOCResponse(BaseModel):
    indicator: NonEmptyText
    indicator_type: NonEmptyText


class IOCEnrichmentResponse(TypedIOCResponse):
    otx_enrichment: dict[str, Any] | None


class CVEEnrichmentResponse(BaseModel):
    cve_id: CVEIdentifier
    enrichment_available: bool
    details: dict[str, Any] | None


class MitreEnrichmentResponse(BaseModel):
    technique_id: MitreTechniqueIdentifier
    enrichment_available: bool
    details: dict[str, Any] | None


class ArticleInvestigationResponse(BaseModel):
    article: ArticleDetailResponse
    typed_iocs: list[TypedIOCResponse]
    ioc_enrichment: list[IOCEnrichmentResponse]
    cve_enrichment: list[CVEEnrichmentResponse]
    mitre_enrichment: list[MitreEnrichmentResponse]