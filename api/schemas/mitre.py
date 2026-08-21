from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)


MitreTechniqueId = Annotated[
    str,
    Field(
        pattern=r"^T\d{4}(?:\.\d{3})?$",
    ),
]

MitreDomain = Literal[
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
]

MitreSearchKeyword = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
    ),
]

MitreSearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=50,
    ),
]

MitreSearchOffset = Annotated[
    int,
    Field(ge=0),
]

NonNegativeResultCount = Annotated[
    int,
    Field(ge=0),
]


class MitreSearchItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: MitreTechniqueId
    name: str
    domain: MitreDomain
    is_subtechnique: bool
    version: str | None
    revoked: bool
    deprecated: bool

class MitreKillChainPhase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kill_chain_name: str
    phase_name: str


class MitreReference(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_name: str
    url: HttpUrl | None = None
    external_id: str | None = None
    description: str | None = None


class MitreTechniqueDetailResponse(
    MitreSearchItemResponse
):
    stix_id: str
    description: str | None
    platforms: list[str] | None
    kill_chain_phases: (
        list[MitreKillChainPhase] | None
    )
    reference_links: list[MitreReference] | None
    created: datetime | None
    modified: datetime | None


class MitreSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keyword: MitreSearchKeyword
    limit: MitreSearchLimit
    offset: MitreSearchOffset
    domain: MitreDomain | None
    include_inactive: bool
    returned_count: NonNegativeResultCount
    results: list[MitreSearchItemResponse]
