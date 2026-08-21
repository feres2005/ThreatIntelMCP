from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)

from api.schemas.cves import CveId


GhsaId = Annotated[
    str,
    Field(
        pattern=(
            r"^GHSA-[a-z0-9]{4}-"
            r"[a-z0-9]{4}-[a-z0-9]{4}$"
        ),
    ),
]

CweId = Annotated[
    str,
    Field(
        pattern=r"^CWE-\d+$",
    ),
]

CvssScore = Annotated[
    float,
    Field(
        ge=0.0,
        le=10.0,
    ),
]

GithubAdvisorySeverity = Literal[
    "low",
    "moderate",
    "high",
    "critical",
]

GithubAdvisorySearchKeyword = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
    ),
]

GithubAdvisorySearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=50,
    ),
]

GithubAdvisorySearchOffset = Annotated[
    int,
    Field(ge=0),
]

NonNegativeResultCount = Annotated[
    int,
    Field(ge=0),
]


class GithubAdvisorySearchItemResponse(
    BaseModel
):
    model_config = ConfigDict(extra="forbid")

    ghsa_id: GhsaId
    cve_id: CveId | None
    summary: str
    severity: GithubAdvisorySeverity
    published_at: datetime | None
    updated_at: datetime | None
    cvss_v3_score: CvssScore | None
    cvss_v4_score: CvssScore | None


class GithubAdvisoryVulnerability(
    BaseModel
):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str | None
    package_name: str | None
    vulnerable_version_range: str | None
    first_patched_version: str | None
    vulnerable_functions: list[str] | None


class GithubAdvisoryDetailResponse(
    GithubAdvisorySearchItemResponse
):
    type: str
    description: str | None
    github_reviewed_at: datetime | None
    nvd_published_at: datetime | None
    withdrawn_at: datetime | None
    cvss_v3_vector: str | None
    cvss_v4_vector: str | None
    cwe_ids: list[CweId] | None
    reference_links: list[HttpUrl] | None
    vulnerabilities: list[
        GithubAdvisoryVulnerability
    ]


class GithubAdvisorySearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keyword: GithubAdvisorySearchKeyword
    limit: GithubAdvisorySearchLimit
    offset: GithubAdvisorySearchOffset
    severity: GithubAdvisorySeverity | None
    returned_count: NonNegativeResultCount
    results: list[
        GithubAdvisorySearchItemResponse
    ]