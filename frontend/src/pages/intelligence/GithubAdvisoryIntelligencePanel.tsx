import {
  useState,
  type FormEvent,
} from 'react'
import { Link } from 'react-router-dom'

import {
  getGithubAdvisoryDetails,
  getGithubAdvisorySupportingArticles,
  searchGithubAdvisories,
} from '../../api/client'
import type {
  GithubAdvisoryDetailResponse,
  GithubAdvisoryEcosystem,
  GithubAdvisorySearchItem,
  GithubAdvisorySeverity,
  GithubAdvisorySupportingArticlesResponse,
} from '../../api/types'

const GHSA_ID_PATTERN =
  /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i

const ECOSYSTEMS: GithubAdvisoryEcosystem[] = [
  'actions',
  'composer',
  'erlang',
  'go',
  'maven',
  'npm',
  'nuget',
  'pip',
  'pub',
  'rubygems',
  'rust',
  'swift',
]

interface AdvisoryDetails {
  advisory: GithubAdvisoryDetailResponse
  evidence: GithubAdvisorySupportingArticlesResponse
}

function formatDate(value: string | null): string {
  if (!value) {
    return 'Unavailable'
  }

  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function getCvssScore(
  advisory: GithubAdvisorySearchItem,
): number | null {
  return (
    advisory.cvss_v4_score
    ?? advisory.cvss_v3_score
  )
}

export function GithubAdvisoryIntelligencePanel() {
  const [keyword, setKeyword] = useState('')
  const [severity, setSeverity] =
    useState<GithubAdvisorySeverity | ''>('')
  const [ecosystem, setEcosystem] =
    useState<GithubAdvisoryEcosystem | ''>('')

  const [results, setResults] =
    useState<GithubAdvisorySearchItem[]>([])
  const [details, setDetails] =
    useState<AdvisoryDetails | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] =
    useState<string | null>(null)

  async function loadAdvisory(
    ghsaId: string,
  ): Promise<void> {
    setLoading(true)
    setError(null)

    try {
      const [advisory, evidence] =
        await Promise.all([
          getGithubAdvisoryDetails(ghsaId),
          getGithubAdvisorySupportingArticles(
            ghsaId,
          ),
        ])

      setDetails({
        advisory,
        evidence,
      })
    } catch (caughtError) {
      setDetails(null)
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Unable to load this advisory.',
      )
    } finally {
      setLoading(false)
    }
  }

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()

    const normalizedKeyword = keyword.trim()

    if (!normalizedKeyword) {
      return
    }

    setError(null)
    setDetails(null)

    if (GHSA_ID_PATTERN.test(normalizedKeyword)) {
      setResults([])
      await loadAdvisory(normalizedKeyword)
      return
    }

    setLoading(true)

    try {
      const response = await searchGithubAdvisories({
        keyword: normalizedKeyword,
        limit: 10,
        severity: severity || undefined,
        ecosystem: ecosystem || undefined,
      })

      setResults(response.results)
    } catch (caughtError) {
      setResults([])
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Unable to search advisories.',
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <section
      className="github-advisory-panel"
      aria-labelledby="github-panel-title"
    >
      <header className="intelligence-section-heading">
        <p>Software supply-chain intelligence</p>
        <h2 id="github-panel-title">
          GitHub Security Advisories
        </h2>
        <span>
          Search reviewed advisories by identifier,
          CVE, package, description, severity or
          ecosystem.
        </span>
      </header>

      <form
        className="github-advisory-search"
        aria-label="GitHub advisory search"
        onSubmit={handleSubmit}
      >
        <label htmlFor="github-search-value">
          Advisory identifier or keyword
        </label>
        <input
          id="github-search-value"
          type="search"
          value={keyword}
          placeholder={
            'Example: GHSA-v667-gc2r-2xm7 '
            + 'or authentication'
          }
          onChange={(event) => {
            setKeyword(event.target.value)
          }}
        />

        <label htmlFor="github-severity">
          Severity
        </label>
        <select
          id="github-severity"
          value={severity}
          onChange={(event) => {
          setSeverity(
            event.target.value as
              | GithubAdvisorySeverity
              | '',
          )
        }}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <label htmlFor="github-ecosystem">
          Package ecosystem
        </label>
        <select
          id="github-ecosystem"
          value={ecosystem}
          onChange={(event) => {
            setEcosystem(
              event.target.value as
                | GithubAdvisoryEcosystem
                | '',
            )
          }}
        >
          <option value="">All ecosystems</option>
          {ECOSYSTEMS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <button
          type="submit"
          disabled={loading || !keyword.trim()}
        >
          {loading
            ? 'Searching…'
            : 'Search GitHub advisories'}
        </button>
      </form>

      {error && (
        <div
          className="intelligence-error"
          role="alert"
        >
          {error}
        </div>
      )}

      {results.length > 0 && (
        <section
          className="github-advisory-results"
          aria-labelledby="github-results-title"
        >
          <header>
            <p>Reviewed advisories</p>
            <h3 id="github-results-title">
              {results.length}{' '}
              {results.length === 1
                ? 'result'
                : 'results'}
            </h3>
          </header>

          <div className="github-advisory-list">
            {results.map((advisory) => (
              <article
                key={advisory.ghsa_id}
                className="github-advisory-card"
              >
                <header>
                  <strong>{advisory.ghsa_id}</strong>
                  <span>{advisory.severity}</span>
                </header>

                <h4>{advisory.summary}</h4>

                <div>
                  <span>
                    {advisory.cve_id
                      ?? 'No associated CVE'}
                  </span>
                  <span>
                    CVSS:{' '}
                    {getCvssScore(advisory)
                      ?? 'Unavailable'}
                  </span>
                  {advisory.ecosystem && (
                    <span>{advisory.ecosystem}</span>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => {
                    void loadAdvisory(
                      advisory.ghsa_id,
                    )
                  }}
                >
                  View {advisory.ghsa_id}
                </button>
              </article>
            ))}
          </div>
        </section>
      )}

      {details && (
        <div className="github-advisory-detail">
          <header>
            <div>
              <p>{details.advisory.severity}</p>
              <h3>{details.advisory.ghsa_id}</h3>
              <span>
                {details.advisory.cve_id
                  ?? 'No associated CVE'}
              </span>
            </div>

            <div>
              <span>CVSS score</span>
              <strong>
                {getCvssScore(details.advisory)
                  ?? 'N/A'}
              </strong>
            </div>
          </header>

          <section>
            <h4>{details.advisory.summary}</h4>
            <p>
              {details.advisory.description
                ?? 'Description unavailable.'}
            </p>

            <dl>
              <div>
                <dt>Published</dt>
                <dd>
                  {formatDate(
                    details.advisory.published_at,
                  )}
                </dd>
              </div>
              <div>
                <dt>Updated</dt>
                <dd>
                  {formatDate(
                    details.advisory.updated_at,
                  )}
                </dd>
              </div>
              <div>
                <dt>Reviewed</dt>
                <dd>
                  {formatDate(
                    details.advisory
                      .github_reviewed_at,
                  )}
                </dd>
              </div>
            </dl>
          </section>

          <section>
            <h4>Affected packages</h4>

            {details.advisory.vulnerabilities.length
              === 0 ? (
                <p>No affected packages recorded.</p>
              ) : (
                <div className="github-package-list">
                  {details.advisory.vulnerabilities.map(
                    (vulnerability, index) => (
                      <article
                        key={[
                          vulnerability.ecosystem,
                          vulnerability.package_name,
                          index,
                        ].join('-')}
                      >
                        <header>
                          <strong>
                            {vulnerability.package_name
                              ?? 'Unknown package'}
                          </strong>
                          <span>
                            {vulnerability.ecosystem
                              ?? 'Unknown ecosystem'}
                          </span>
                        </header>

                        <p>
                          Vulnerable:{' '}
                          {vulnerability
                            .vulnerable_version_range
                            ?? 'Unavailable'}
                        </p>
                        <p>
                          First patched:{' '}
                          {vulnerability
                            .first_patched_version
                            ?? 'Not recorded'}
                        </p>
                      </article>
                    ),
                  )}
                </div>
              )}
          </section>

          <section>
            <header>
              <h4>Supporting articles</h4>
              <span>
                {details.evidence
                  .supporting_article_count}{' '}
                local{' '}
                {details.evidence
                  .supporting_article_count === 1
                  ? 'mention'
                  : 'mentions'}
              </span>
            </header>

            {details.evidence.articles.length === 0
              ? (
                <p>No local article evidence.</p>
              ) : (
                <div className="github-article-list">
                  {details.evidence.articles.map(
                    (article) => (
                      <article key={article.article_id}>
                        <header>
                          <span>
                            {article.severity
                              ?? 'Unknown severity'}
                          </span>
                          <span>
                            {article.confidence_score
                              === null
                              ? 'Unknown confidence'
                              : `${Math.round(
                                article
                                  .confidence_score
                                * 100,
                              )}% confidence`}
                          </span>
                        </header>

                        <h5>{article.title}</h5>
                        <p>
                          {article.source
                            ?? 'Unknown source'}
                        </p>

                        <div>
                          <Link
                            to={
                              `/articles/`
                              + article.article_id
                            }
                          >
                            Open investigation
                          </Link>
                          <a
                            href={article.link}
                            target="_blank"
                            rel="noreferrer"
                          >
                            Open source
                          </a>
                        </div>
                      </article>
                    ),
                  )}
                </div>
              )}
          </section>
        </div>
      )}
    </section>
  )
}