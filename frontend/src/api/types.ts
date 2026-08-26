export interface HealthResponse {
  status: string
  service: string
  version: string
}

export interface PipelineWorkPending {
  article_processing: number
  embedding_indexing: number
}

export interface PipelineCoverage {
  processing_percent: number
  analysis_percent: number
  embedding_percent: number
}

export interface PipelineCounts {
  total_articles: number
  processed_articles: number
  pending_articles: number
  analyzed_articles: number
  processed_without_analysis: number
  pending_with_analysis: number
  typed_ioc_rows: number
  articles_with_typed_iocs: number
  article_embeddings: number
  articles_missing_embeddings: number
  enriched_cves: number
  cached_otx_indicators: number
  mitre_techniques: number
  github_advisories: number
}

export interface PipelineStatusResponse {
  operation: 'get_pipeline_status'
  health_status: string
  work_pending: PipelineWorkPending
  coverage: PipelineCoverage
  counts: PipelineCounts
  warnings: string[]
}
export type TopicTrend =
  | 'rising'
  | 'stable'
  | 'declining'

export interface RepresentativeTopicArticle {
  article_id: number
  title: string
  link: string
  source: string
  published: string
  similarity_to_centroid: number
}

export interface EmergingTopic {
  label: string
  keywords: string[]
  article_count: number
  recent_article_count: number
  previous_article_count: number
  recent_share: number
  previous_share: number
  trend: TopicTrend
  trend_score: number
  sources: string[]
  classifications: string[]
  severities: string[]
  cves: string[]
  malware: string[]
  mitre_techniques: string[]
  apt_groups: string[]
  targeted_sectors: string[]
  affected_technologies: string[]
  representative_articles:
    RepresentativeTopicArticle[]
}

export interface EmergingTopicsResponse {
  generated_at: string
  observation_days: number
  recent_days: number
  limit: number
  considered_article_count: number
  clustered_article_count: number
  noise_article_count: number
  topics: EmergingTopic[]
}

export interface ArticleSearchResult {
  article_id: number
  title: string
  summary: string
  severity: string | null
  confidence_score: number
  cves: string[]
  malware: string[]
  mitre_techniques: string[]
}

export interface ArticleSearchResponse {
  keyword: string
  limit: number
  offset: number
  returned_count: number
  results: ArticleSearchResult[]
}

export interface ArticleDetailResponse {
  article_id: number
  title: string
  link: string
  published: string | null
  summary: string
  classification: string[]
  severity: string
  confidence_score: number
  iocs: string[]
  cves: string[]
  malware: string[]
  mitre_techniques: string[]
  apt_groups: string[]
  targeted_sectors: string[]
  affected_technologies: string[]
}

export interface MitreKillChainPhase {
  phase_name: string
  kill_chain_name: string
}

export interface MitreTechniqueDetails {
  name: string
  domain: string
  is_subtechnique: boolean
  platforms: string[]
  kill_chain_phases: MitreKillChainPhase[]
  version: string
  revoked: boolean
  deprecated: boolean
}

export interface MitreArticleEnrichment {
  technique_id: string
  enrichment_available: boolean
  details: MitreTechniqueDetails | null
}

export interface ArticleInvestigationResponse {
  article: ArticleDetailResponse
  typed_iocs: unknown[]
  ioc_enrichment: unknown[]
  cve_enrichment: unknown[]
  mitre_enrichment: MitreArticleEnrichment[]
}

export interface ScoreComponent {
  points: number
  maximum_points: number
  [key: string]: unknown
}

export interface ThreatAssessmentResponse {
  scoring_version: string
  threat_score: number
  threat_level: string
  evidence_present: boolean
  components: Record<string, ScoreComponent>
  warnings: string[]
}

export interface ConfidenceAssessmentResponse {
  scoring_version: string
  confidence_score: number
  confidence_level: string
  components: Record<string, ScoreComponent>
  warnings: string[]
}

export interface PriorityResponse {
  threat_level: string
  confidence_level: string
  priority_code: string
  priority_label: string
  recommended_action: string
}

export interface ScoringWarningResponse {
  source: 'threat' | 'confidence'
  message: string
}

export interface ArticleScoringResponse {
  target: {
    entity_type: 'article'
    article_id: number
    title: string
  }
  otx_selection: unknown | null
  scoring_version: string
  threat: ThreatAssessmentResponse
  confidence: ConfidenceAssessmentResponse
  priority: PriorityResponse
  warnings: ScoringWarningResponse[]
}

export interface SemanticArticleSearchResult {
  article_id: number
  title: string
  link: string
  source: string
  published: string | null
  summary: string | null
  analysis_available: boolean
  similarity: number
}

export interface SemanticArticleSearchResponse {
  search_query: string
  limit: number
  returned_count: number
  results: SemanticArticleSearchResult[]
}

export type IndicatorType =
  | 'IPv4'
  | 'IPv6'
  | 'URL'
  | 'domain'
  | 'FileHash-MD5'
  | 'FileHash-SHA1'
  | 'FileHash-SHA256'

export interface SupportingIndicatorArticle {
  article_id: number
  title: string
  link: string
  published: string | null
  severity: string | null
  confidence_score: number | null
}

export interface RelatedEntityEvidence {
  value: string
  supporting_article_count: number
  supporting_article_ids: number[]
}

export interface IndicatorRelatedEntities {
  cves: RelatedEntityEvidence[]
  malware: RelatedEntityEvidence[]
  mitre_techniques: RelatedEntityEvidence[]
  apt_groups: RelatedEntityEvidence[]
  targeted_sectors: RelatedEntityEvidence[]
  affected_technologies: RelatedEntityEvidence[]
}

export interface OtxValidation {
  name: string
  source: string
  message: string
}

export interface OtxIndicatorEnrichment {
  indicator: string
  indicator_type: IndicatorType
  reputation: number | string | null
  pulse_count: number
  country: string | null
  country_code: string | null
  asn: string | number | null
  malware_families: string[]
  adversaries: string[]
  industries: string[]
  validation: OtxValidation[]
  sections: string[]
  last_checked: string
}

export interface VirusTotalCommunityVotes {
  harmless: number
  malicious: number
}

export interface VirusTotalDetection {
  engine_name: string
  category: 'malicious' | 'suspicious'
  result: string | null
  method: string | null
}

export interface VirusTotalIndicatorEnrichment {
  indicator: string
  indicator_type: IndicatorType
  report_available: boolean
  resource_type:
    | 'file'
    | 'ip_address'
    | 'domain'
    | 'url'
    | null
  resource_id: string | null
  malicious_count: number
  suspicious_count: number
  harmless_count: number
  undetected_count: number
  timeout_count: number
  failure_count: number
  type_unsupported_count: number
  confirmed_timeout_count: number
  total_engine_count: number
  total_result_count: number
  reputation: number | null
  community_votes: VirusTotalCommunityVotes
  detections: VirusTotalDetection[]
  categories: string[]
  tags: string[]
  names: string[]
  meaningful_name: string | null
  file_type: string | null
  country: string | null
  asn: number | null
  as_owner: string | null
  last_analysis_date: string | null
  permalink: string | null
  last_checked: string
  source: 'virustotal'
  cache_status:
    | 'fresh'
    | 'refreshed'
    | 'stale_fallback'
  is_stale: boolean
}

export interface IndicatorCorrelationResponse {
  indicator: string
  indicator_type: IndicatorType
  supporting_article_count: number
  supporting_article_ids: number[]
  supporting_articles: SupportingIndicatorArticle[]
  related_entities: IndicatorRelatedEntities
  otx_enrichment: OtxIndicatorEnrichment | null
  virustotal_enrichment:
    VirusTotalIndicatorEnrichment | null
}
export interface IndicatorScoringTarget {
  entity_type: 'indicator'
  indicator: string
  indicator_type: IndicatorType
}

export interface IndicatorScoringResponse {
  target: IndicatorScoringTarget
  scoring_version: string
  threat: ArticleScoringResponse['threat']
  confidence: ArticleScoringResponse['confidence']
  priority: ArticleScoringResponse['priority']
  warnings: ArticleScoringResponse['warnings']
}

export interface CveSearchItem {
  cve_id: string
  description: string | null
  cvss_score: number | null
  severity: string | null
  published: string | null
  last_modified: string | null
}

export interface CveSearchResponse {
  keyword: string
  limit: number
  offset: number
  returned_count: number
  results: CveSearchItem[]
}

export interface CveDetailResponse
  extends CveSearchItem {
  reference_links: string[]
  enriched_at: string | null
}

export interface CveSupportingArticle {
  article_id: number
  title: string
  link: string
  source: string
  published: string | null
  severity: string | null
  confidence_score: number | null
}

export interface CveSupportingArticlesResponse {
  cve_id: string
  limit: number
  supporting_article_count: number
  returned_count: number
  articles: CveSupportingArticle[]
}
export type MitreDomain =
  | 'enterprise-attack'
  | 'mobile-attack'
  | 'ics-attack'

export interface MitreSearchItem {
  technique_id: string
  name: string
  domain: MitreDomain
  is_subtechnique: boolean
  version: string | null
  revoked: boolean
  deprecated: boolean
}

export interface MitreSearchResponse {
  keyword: string
  limit: number
  offset: number
  domain: MitreDomain | null
  include_inactive: boolean
  returned_count: number
  results: MitreSearchItem[]
}

export interface MitreKillChainPhase {
  kill_chain_name: string
  phase_name: string
}

export interface MitreReference {
  source_name: string
  url: string | null
  external_id: string | null
  description: string | null
}

export interface MitreTechniqueDetail
  extends MitreSearchItem {
  stix_id: string
  description: string | null
  platforms: string[] | null
  kill_chain_phases:
    MitreKillChainPhase[] | null
  reference_links: MitreReference[] | null
  created: string | null
  modified: string | null
}

export interface MitreSupportingArticle {
  article_id: number
  title: string
  link: string
  source: string
  published: string | null
  severity: string | null
  confidence_score: number | null
}

export interface MitreSupportingArticlesResponse {
  technique_id: string
  limit: number
  supporting_article_count: number
  returned_count: number
  articles: MitreSupportingArticle[]
}

export type GithubAdvisorySeverity =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type GithubAdvisoryEcosystem =
  | 'actions'
  | 'composer'
  | 'erlang'
  | 'go'
  | 'maven'
  | 'npm'
  | 'nuget'
  | 'pip'
  | 'pub'
  | 'rubygems'
  | 'rust'
  | 'swift'

export interface GithubAdvisorySearchItem {
  ghsa_id: string
  cve_id: string | null
  summary: string
  severity: GithubAdvisorySeverity
  ecosystem: GithubAdvisoryEcosystem | null
  published_at: string | null
  updated_at: string | null
  cvss_v3_score: number | null
  cvss_v4_score: number | null
}

export interface GithubAdvisorySearchResponse {
  keyword: string
  limit: number
  offset: number
  severity: GithubAdvisorySeverity | null
  ecosystem: GithubAdvisoryEcosystem | null
  returned_count: number
  results: GithubAdvisorySearchItem[]
}

export interface GithubAdvisoryVulnerability {
  ecosystem: GithubAdvisoryEcosystem | null
  package_name: string | null
  vulnerable_version_range: string | null
  first_patched_version: string | null
  vulnerable_functions: string[] | null
}

export interface GithubAdvisoryDetailResponse
  extends GithubAdvisorySearchItem {
  type: string
  description: string | null
  github_reviewed_at: string | null
  nvd_published_at: string | null
  withdrawn_at: string | null
  cvss_v3_vector: string | null
  cvss_v4_vector: string | null
  cwe_ids: string[] | null
  reference_links: string[] | null
  vulnerabilities: GithubAdvisoryVulnerability[]
}

export interface GithubSupportingArticle {
  article_id: number
  title: string
  link: string
  source: string | null
  published: string | null
  severity: string | null
  confidence_score: number | null
}

export interface GithubAdvisorySupportingArticlesResponse {
  ghsa_id: string
  cve_id: string | null
  limit: number
  supporting_article_count: number
  returned_count: number
  articles: GithubSupportingArticle[]
}

export type ThreatEntityType =
  | 'malware'
  | 'apt_group'
  | 'targeted_sector'
  | 'affected_technology'

export interface ThreatEntitySearchItem {
  value: string
  supporting_article_count: number
  latest_seen: string | null
}

export interface ThreatEntitySearchResponse {
  entity_type: ThreatEntityType
  keyword: string
  limit: number
  offset: number
  returned_count: number
  results: ThreatEntitySearchItem[]
}

export interface ThreatEntityArticle {
  article_id: number
  title: string
  link: string
  source: string | null
  published: string | null
  summary: string | null
  severity: string | null
  confidence_score: number | null
  cves: string[]
  malware: string[]
  mitre_techniques: string[]
  apt_groups: string[]
  targeted_sectors: string[]
  affected_technologies: string[]
}

export interface ThreatEntityEvidenceResponse {
  entity_type: ThreatEntityType
  value: string
  limit: number
  supporting_article_count: number
  returned_count: number
  articles: ThreatEntityArticle[]
}