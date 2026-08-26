import type {
  ArticleDetailResponse,
  ArticleInvestigationResponse,
  ArticleScoringResponse,
  ArticleSearchResponse,
  EmergingTopicsResponse,
  HealthResponse,
  PipelineStatusResponse,
  SemanticArticleSearchResponse,
  IndicatorCorrelationResponse,
  IndicatorScoringResponse,
  CveDetailResponse,
  CveSearchResponse,
  CveSupportingArticlesResponse,
  MitreDomain,
  MitreSearchResponse,
  MitreSupportingArticlesResponse,
  MitreTechniqueDetail,
  GithubAdvisoryDetailResponse,
  GithubAdvisoryEcosystem,
  GithubAdvisorySearchResponse,
  GithubAdvisorySeverity,
  GithubAdvisorySupportingArticlesResponse,
  ThreatEntityEvidenceResponse,
  ThreatEntitySearchResponse,
  ThreatEntityType,
} from './types'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function getErrorMessage(
  response: Response,
): Promise<string> {
  try {
    const body = await response.json() as {
      detail?: unknown
    }

    if (
      typeof body.detail === 'string'
      && body.detail.trim()
    ) {
      return body.detail
    }
  } catch {
    // The fallback below handles non-JSON errors.
  }

  return `Request failed with status ${response.status}.`
}

async function requestJson<T>(
  path: string,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(path, {
    headers: {
      Accept: 'application/json',
    },
    signal,
  })

  if (!response.ok) {
    throw new ApiError(
      response.status,
      await getErrorMessage(response),
    )
  }

  return await response.json() as T
}

export function getHealth(
  signal?: AbortSignal,
): Promise<HealthResponse> {
  return requestJson('/health', signal)
}

export function getPipelineStatus(
  signal?: AbortSignal,
): Promise<PipelineStatusResponse> {
  return requestJson(
    '/api/v1/pipeline/status',
    signal,
  )
}
export interface EmergingTopicsParameters {
  observationDays?: number
  recentDays?: number
  limit?: number
}

export function getEmergingTopics(
  {
    observationDays = 30,
    recentDays = 7,
    limit = 10,
  }: EmergingTopicsParameters = {},
  signal?: AbortSignal,
): Promise<EmergingTopicsResponse> {
  const parameters = new URLSearchParams({
    observation_days: String(observationDays),
    recent_days: String(recentDays),
    limit: String(limit),
  })

  return requestJson(
    `/api/v1/topics/emerging?${parameters}`,
    signal,
  )
}
export interface ArticleSearchParameters {
  keyword: string
  limit?: number
  offset?: number
}

export async function searchArticles(
  {
    keyword,
    limit = 20,
    offset = 0,
  }: ArticleSearchParameters,
  signal?: AbortSignal,
): Promise<ArticleSearchResponse> {
  const normalizedKeyword = keyword.trim()

  if (!normalizedKeyword) {
    throw new Error(
      'Search keyword is required.',
    )
  }

  const parameters = new URLSearchParams({
    keyword: normalizedKeyword,
    limit: String(limit),
    offset: String(offset),
  })

  return await requestJson(
    `/api/v1/articles?${parameters}`,
    signal,
  )
}
export interface SemanticArticleSearchParameters {
  searchQuery: string
  limit?: number
}

export async function semanticSearchArticles(
  {
    searchQuery,
    limit = 10,
  }: SemanticArticleSearchParameters,
  signal?: AbortSignal,
): Promise<SemanticArticleSearchResponse> {
  const normalizedQuery = searchQuery.trim()

  if (!normalizedQuery) {
    throw new Error(
      'Semantic search query is required.',
    )
  }

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'Semantic search limit must be between 1 and 50.',
    )
  }

  const parameters = new URLSearchParams({
    search_query: normalizedQuery,
    limit: String(limit),
  })

  return await requestJson(
    `/api/v1/search/articles/semantic?${parameters}`,
    signal,
  )
}

function validateArticleId(
  articleId: number,
): void {
  if (
    !Number.isInteger(articleId)
    || articleId <= 0
  ) {
    throw new Error(
      'Article ID must be a positive integer.',
    )
  }
}

export function getArticleDetails(
  articleId: number,
  signal?: AbortSignal,
): Promise<ArticleDetailResponse> {
  validateArticleId(articleId)

  return requestJson(
    `/api/v1/articles/${articleId}`,
    signal,
  )
}

export function getArticleInvestigation(
  articleId: number,
  signal?: AbortSignal,
): Promise<ArticleInvestigationResponse> {
  validateArticleId(articleId)

  return requestJson(
    `/api/v1/articles/${articleId}/investigation`,
    signal,
  )
}

export function getArticleScoring(
  articleId: number,
  signal?: AbortSignal,
): Promise<ArticleScoringResponse> {
  validateArticleId(articleId)

  return requestJson(
    `/api/v1/articles/${articleId}/score`,
    signal,
  )
}
export interface IndicatorLookupParameters {
  indicator: string
  includeOtx?: boolean
  includeVirusTotal?: boolean
}

export function getIndicatorCorrelation(
  {
    indicator,
    includeOtx = false,
    includeVirusTotal = false,
  }: IndicatorLookupParameters,
  signal?: AbortSignal,
): Promise<IndicatorCorrelationResponse> {
  const normalizedIndicator = indicator.trim()

  if (!normalizedIndicator) {
    throw new Error(
      'Indicator is required.',
    )
  }

  const parameters = new URLSearchParams({
    indicator: normalizedIndicator,
    include_otx: String(includeOtx),
    include_virustotal: String(
      includeVirusTotal,
    ),
  })

  return requestJson(
    (
      '/api/v1/indicators/correlation'
      + `?${parameters}`
    ),
    signal,
  )
}
export function getIndicatorScoring(
  {
    indicator,
    includeOtx = false,
    includeVirusTotal = false,
  }: IndicatorLookupParameters,
  signal?: AbortSignal,
): Promise<IndicatorScoringResponse> {
  const normalizedIndicator = indicator.trim()

  if (!normalizedIndicator) {
    throw new Error(
      'Indicator is required.',
    )
  }

  const parameters = new URLSearchParams({
    indicator: normalizedIndicator,
    include_otx: String(includeOtx),
    include_virustotal: String(
      includeVirusTotal,
    ),
  })

  return requestJson(
    (
      '/api/v1/indicators/score'
      + `?${parameters}`
    ),
    signal,
  )
}

const CVE_ID_PATTERN =
  /^CVE-\d{4}-\d{4,}$/i

function normalizeCveId(
  cveId: string,
): string {
  const normalizedCveId = cveId
    .trim()
    .toUpperCase()

  if (!CVE_ID_PATTERN.test(normalizedCveId)) {
    throw new Error(
      'CVE ID must follow the format '
      + 'CVE-YYYY-NNNN.',
    )
  }

  return normalizedCveId
}

export interface CveSearchParameters {
  keyword: string
  limit?: number
  offset?: number
}

export function searchCves(
  {
    keyword,
    limit = 10,
    offset = 0,
  }: CveSearchParameters,
  signal?: AbortSignal,
): Promise<CveSearchResponse> {
  const normalizedKeyword = keyword.trim()

  if (
    !normalizedKeyword
    || normalizedKeyword.length > 200
  ) {
    throw new Error(
      'CVE search keyword must contain '
      + 'between 1 and 200 characters.',
    )
  }

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'CVE search limit must be between '
      + '1 and 50.',
    )
  }

  if (
    !Number.isInteger(offset)
    || offset < 0
  ) {
    throw new Error(
      'CVE search offset must be '
      + 'non-negative.',
    )
  }

  const parameters = new URLSearchParams({
    keyword: normalizedKeyword,
    limit: String(limit),
    offset: String(offset),
  })

  return requestJson(
    `/api/v1/cves?${parameters}`,
    signal,
  )
}

export function getCveDetails(
  cveId: string,
  signal?: AbortSignal,
): Promise<CveDetailResponse> {
  const normalizedCveId = normalizeCveId(
    cveId,
  )

  return requestJson(
    `/api/v1/cves/${normalizedCveId}`,
    signal,
  )
}

export function getCveSupportingArticles(
  cveId: string,
  limit = 20,
  signal?: AbortSignal,
): Promise<CveSupportingArticlesResponse> {
  const normalizedCveId = normalizeCveId(
    cveId,
  )

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'Supporting article limit must be '
      + 'between 1 and 50.',
    )
  }

  const parameters = new URLSearchParams({
    limit: String(limit),
  })

  return requestJson(
    (
      `/api/v1/cves/${normalizedCveId}`
      + `/articles?${parameters}`
    ),
    signal,
  )
}
const MITRE_TECHNIQUE_ID_PATTERN =
  /^T\d{4}(?:\.\d{3})?$/i

function normalizeMitreTechniqueId(
  techniqueId: string,
): string {
  const normalizedTechniqueId =
    techniqueId.trim().toUpperCase()

  if (
    !MITRE_TECHNIQUE_ID_PATTERN.test(
      normalizedTechniqueId,
    )
  ) {
    throw new Error(
      'MITRE technique ID must follow '
      + 'the format TNNNN or TNNNN.NNN.',
    )
  }

  return normalizedTechniqueId
}

export interface MitreSearchParameters {
  keyword: string
  limit?: number
  offset?: number
  domain?: MitreDomain
  includeInactive?: boolean
}

export function searchMitreTechniques(
  {
    keyword,
    limit = 10,
    offset = 0,
    domain,
    includeInactive = false,
  }: MitreSearchParameters,
  signal?: AbortSignal,
): Promise<MitreSearchResponse> {
  const normalizedKeyword = keyword.trim()

  if (
    !normalizedKeyword
    || normalizedKeyword.length > 200
  ) {
    throw new Error(
      'MITRE search keyword must contain '
      + 'between 1 and 200 characters.',
    )
  }

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'MITRE search limit must be between '
      + '1 and 50.',
    )
  }

  if (
    !Number.isInteger(offset)
    || offset < 0
  ) {
    throw new Error(
      'MITRE search offset must be '
      + 'non-negative.',
    )
  }

  if (typeof includeInactive !== 'boolean') {
    throw new Error(
      'Include-inactive must be a boolean.',
    )
  }

  const parameters = new URLSearchParams({
    keyword: normalizedKeyword,
    limit: String(limit),
    offset: String(offset),
    include_inactive: String(includeInactive),
  })

  if (domain) {
    parameters.set('domain', domain)
  }

  return requestJson(
    (
      '/api/v1/mitre/techniques'
      + `?${parameters}`
    ),
    signal,
  )
}

export function getMitreTechniqueDetails(
  techniqueId: string,
  signal?: AbortSignal,
): Promise<MitreTechniqueDetail> {
  const normalizedTechniqueId =
    normalizeMitreTechniqueId(techniqueId)

  return requestJson(
    (
      '/api/v1/mitre/techniques/'
      + normalizedTechniqueId
    ),
    signal,
  )
}

export function getMitreSupportingArticles(
  techniqueId: string,
  limit = 20,
  signal?: AbortSignal,
): Promise<MitreSupportingArticlesResponse> {
  const normalizedTechniqueId =
    normalizeMitreTechniqueId(techniqueId)

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'MITRE supporting article limit '
      + 'must be between 1 and 50.',
    )
  }

  const parameters = new URLSearchParams({
    limit: String(limit),
  })

  return requestJson(
    (
      '/api/v1/mitre/techniques/'
      + `${normalizedTechniqueId}/articles`
      + `?${parameters}`
    ),
    signal,
  )
}
const GHSA_ID_PATTERN =
  /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i

function normalizeGithubAdvisoryId(
  ghsaId: string,
): string {
  const cleanedGhsaId = ghsaId.trim()

  if (!GHSA_ID_PATTERN.test(cleanedGhsaId)) {
    throw new Error(
      'GitHub advisory ID must follow the '
      + 'format GHSA-XXXX-XXXX-XXXX.',
    )
  }

  return (
    'GHSA-'
    + cleanedGhsaId.slice(5).toLowerCase()
  )
}

export interface GithubAdvisorySearchParameters {
  keyword: string
  limit?: number
  offset?: number
  severity?: GithubAdvisorySeverity
  ecosystem?: GithubAdvisoryEcosystem
}

export function searchGithubAdvisories(
  {
    keyword,
    limit = 10,
    offset = 0,
    severity,
    ecosystem,
  }: GithubAdvisorySearchParameters,
  signal?: AbortSignal,
): Promise<GithubAdvisorySearchResponse> {
  const normalizedKeyword = keyword.trim()

  if (
    !normalizedKeyword
    || normalizedKeyword.length > 200
  ) {
    throw new Error(
      'GitHub advisory search keyword must '
      + 'contain between 1 and 200 characters.',
    )
  }

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'GitHub advisory search limit must '
      + 'be between 1 and 50.',
    )
  }

  if (
    !Number.isInteger(offset)
    || offset < 0
  ) {
    throw new Error(
      'GitHub advisory search offset must '
      + 'be non-negative.',
    )
  }

  const parameters = new URLSearchParams({
    keyword: normalizedKeyword,
    limit: String(limit),
    offset: String(offset),
  })

  if (severity) {
    parameters.set('severity', severity)
  }

  if (ecosystem) {
    parameters.set('ecosystem', ecosystem)
  }

  return requestJson(
    `/api/v1/github/advisories?${parameters}`,
    signal,
  )
}

export function getGithubAdvisoryDetails(
  ghsaId: string,
  signal?: AbortSignal,
): Promise<GithubAdvisoryDetailResponse> {
  const normalizedGhsaId =
    normalizeGithubAdvisoryId(ghsaId)

  return requestJson(
    `/api/v1/github/advisories/${normalizedGhsaId}`,
    signal,
  )
}

export function getGithubAdvisorySupportingArticles(
  ghsaId: string,
  limit = 20,
  signal?: AbortSignal,
): Promise<GithubAdvisorySupportingArticlesResponse> {
  const normalizedGhsaId =
    normalizeGithubAdvisoryId(ghsaId)

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'Supporting article limit must be '
      + 'between 1 and 50.',
    )
  }

  const parameters = new URLSearchParams({
    limit: String(limit),
  })

  return requestJson(
    (
      `/api/v1/github/advisories/${normalizedGhsaId}`
      + `/articles?${parameters}`
    ),
    signal,
  )
}

const THREAT_ENTITY_TYPES =
  new Set<ThreatEntityType>([
    'malware',
    'apt_group',
    'targeted_sector',
    'affected_technology',
  ])

function validateThreatEntityType(
  entityType: ThreatEntityType,
): void {
  if (!THREAT_ENTITY_TYPES.has(entityType)) {
    throw new Error(
      'Unsupported threat entity type.',
    )
  }
}

export interface ThreatEntitySearchParameters {
  entityType: ThreatEntityType
  keyword: string
  limit?: number
  offset?: number
}

export function searchThreatEntities(
  {
    entityType,
    keyword,
    limit = 10,
    offset = 0,
  }: ThreatEntitySearchParameters,
  signal?: AbortSignal,
): Promise<ThreatEntitySearchResponse> {
  validateThreatEntityType(entityType)

  const normalizedKeyword = keyword.trim()

  if (
    !normalizedKeyword
    || normalizedKeyword.length > 200
  ) {
    throw new Error(
      'Entity search keyword must contain '
      + 'between 1 and 200 characters.',
    )
  }

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'Entity search limit must be between '
      + '1 and 50.',
    )
  }

  if (
    !Number.isInteger(offset)
    || offset < 0
  ) {
    throw new Error(
      'Entity search offset must be '
      + 'non-negative.',
    )
  }

  const parameters = new URLSearchParams({
    entity_type: entityType,
    keyword: normalizedKeyword,
    limit: String(limit),
    offset: String(offset),
  })

  return requestJson(
    `/api/v1/entities?${parameters}`,
    signal,
  )
}

export interface ThreatEntityEvidenceParameters {
  entityType: ThreatEntityType
  value: string
  limit?: number
}

export function getThreatEntityEvidence(
  {
    entityType,
    value,
    limit = 20,
  }: ThreatEntityEvidenceParameters,
  signal?: AbortSignal,
): Promise<ThreatEntityEvidenceResponse> {
  validateThreatEntityType(entityType)

  const normalizedValue = value.trim()

  if (
    !normalizedValue
    || normalizedValue.length > 500
  ) {
    throw new Error(
      'Entity value must contain between '
      + '1 and 500 characters.',
    )
  }

  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > 50
  ) {
    throw new Error(
      'Entity evidence limit must be between '
      + '1 and 50.',
    )
  }

  const parameters = new URLSearchParams({
    entity_type: entityType,
    value: normalizedValue,
    limit: String(limit),
  })

  return requestJson(
    `/api/v1/entities/evidence?${parameters}`,
    signal,
  )
}