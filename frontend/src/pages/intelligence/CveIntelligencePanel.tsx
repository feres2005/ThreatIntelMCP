import {
  useEffect,
  useRef,
  useState,
} from 'react'
import type {
  FormEvent,
} from 'react'
import {
  Link,
} from 'react-router-dom'

import {
  getCveDetails,
  getCveSupportingArticles,
  searchCves,
} from '../../api/client'
import type {
  CveDetailResponse,
  CveSearchItem,
  CveSupportingArticlesResponse,
} from '../../api/types'

const EXACT_CVE_PATTERN =
  /^CVE-\d{4}-\d{4,}$/i

interface SelectedCve {
  detail: CveDetailResponse
  evidence: CveSupportingArticlesResponse
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Unavailable'
  }

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat(
    undefined,
    {
      dateStyle: 'medium',
      timeStyle: 'short',
    },
  ).format(date)
}

export function CveIntelligencePanel() {
  const [query, setQuery] = useState('')
  const [results, setResults] =
    useState<CveSearchItem[] | null>(null)
  const [selectedCve, setSelectedCve] =
    useState<SelectedCve | null>(null)
  const [loading, setLoading] =
    useState(false)
  const [error, setError] =
    useState<string | null>(null)

  const requestController =
    useRef<AbortController | null>(null)

  useEffect(() => {
    return () => {
      requestController.current?.abort()
    }
  }, [])

  function beginRequest(): AbortController {
    requestController.current?.abort()

    const controller = new AbortController()
    requestController.current = controller

    return controller
  }

  async function loadCve(
    cveId: string,
  ): Promise<void> {
    const controller = beginRequest()

    setLoading(true)
    setError(null)
    setSelectedCve(null)

    try {
      const [detail, evidence] =
        await Promise.all([
          getCveDetails(
            cveId,
            controller.signal,
          ),
          getCveSupportingArticles(
            cveId,
            20,
            controller.signal,
          ),
        ])

      if (!controller.signal.aborted) {
        setSelectedCve({
          detail,
          evidence,
        })
      }
    } catch (requestError) {
      if (!controller.signal.aborted) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : 'CVE lookup failed.',
        )
      }
    } finally {
      if (
        requestController.current === controller
      ) {
        setLoading(false)
      }
    }
  }

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()

    const normalizedQuery = query.trim()

    if (!normalizedQuery) {
      setError('CVE search value is required.')
      return
    }

    setError(null)
    setSelectedCve(null)

    if (
      EXACT_CVE_PATTERN.test(normalizedQuery)
    ) {
      setResults(null)

      await loadCve(
        normalizedQuery.toUpperCase(),
      )
      return
    }

    const controller = beginRequest()

    setLoading(true)
    setResults(null)

    try {
      const response = await searchCves(
        {
          keyword: normalizedQuery,
          limit: 10,
          offset: 0,
        },
        controller.signal,
      )

      if (!controller.signal.aborted) {
        setResults(response.results)
      }
    } catch (requestError) {
      if (!controller.signal.aborted) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : 'CVE search failed.',
        )
      }
    } finally {
      if (
        requestController.current === controller
      ) {
        setLoading(false)
      }
    }
  }

  return (
    <section
      className="cve-intelligence-panel"
      aria-labelledby="cve-panel-title"
    >
      <header className="intelligence-section-heading">
        <p>Vulnerability intelligence</p>
        <h2 id="cve-panel-title">
          CVE Intelligence
        </h2>
        <span>
          Search cached vulnerabilities or enter
          an exact CVE identifier to retrieve and
          persist NVD intelligence.
        </span>
      </header>

      <form
        className="cve-search"
        aria-label="CVE intelligence search"
        onSubmit={handleSubmit}
      >
        <label htmlFor="cve-search-value">
          CVE identifier, description or severity
        </label>

        <input
          id="cve-search-value"
          type="search"
          value={query}
          placeholder="Example: CVE-2026-50522 or critical"
          onChange={(event) => {
            setQuery(event.target.value)
          }}
        />

        <button
          type="submit"
          disabled={loading}
        >
          {loading
            ? 'Searching...'
            : 'Search CVE intelligence'}
        </button>
      </form>

      {loading && (
        <div
          className="intelligence-status"
          role="status"
        >
          Loading CVE intelligence...
        </div>
      )}

      {error && (
        <div
          className="intelligence-error"
          role="alert"
        >
          {error}
        </div>
      )}

      {results !== null && (
        <section
          className="cve-search-results"
          aria-labelledby="cve-results-title"
        >
          <header>
            <p>Cached intelligence</p>
            <h3 id="cve-results-title">
              {results.length} CVE result
              {results.length === 1 ? '' : 's'}
            </h3>
          </header>

          {results.length === 0 ? (
            <p>
              No cached CVEs matched this search.
              Try an exact CVE identifier to query
              NVD.
            </p>
          ) : (
            <div className="cve-result-list">
              {results.map((cve) => (
                <article
                  className="cve-result-card"
                  key={cve.cve_id}
                >
                  <header>
                    <strong>{cve.cve_id}</strong>
                    <span>
                      {cve.severity ?? 'UNKNOWN'}
                    </span>
                  </header>

                  <p>
                    {cve.description
                      ?? 'Description unavailable.'}
                  </p>

                  <div>
                    <span>
                      CVSS:{' '}
                      {cve.cvss_score ?? 'Unavailable'}
                    </span>

                    <span>
                      Published:{' '}
                      {formatDate(cve.published)}
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      void loadCve(cve.cve_id)
                    }}
                  >
                    View {cve.cve_id}
                  </button>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {selectedCve && (
        <div className="cve-detail">
          <header className="cve-detail-heading">
            <div>
              <p>
                {selectedCve.detail.severity
                  ?? 'UNKNOWN'}
              </p>
              <h3>
                {selectedCve.detail.cve_id}
              </h3>
            </div>

            <div>
              <span>CVSS score</span>
              <strong>
                {selectedCve.detail.cvss_score
                  ?? 'Unavailable'}
              </strong>
            </div>
          </header>

          <section
            className="cve-detail-panel"
            aria-labelledby="cve-description-title"
          >
            <h4 id="cve-description-title">
              Vulnerability description
            </h4>

            <p>
              {selectedCve.detail.description
                ?? 'Description unavailable.'}
            </p>

            <dl className="cve-metadata">
              <div>
                <dt>Published</dt>
                <dd>
                  {formatDate(
                    selectedCve.detail.published,
                  )}
                </dd>
              </div>

              <div>
                <dt>Last modified</dt>
                <dd>
                  {formatDate(
                    selectedCve.detail.last_modified,
                  )}
                </dd>
              </div>

              <div>
                <dt>Locally enriched</dt>
                <dd>
                  {formatDate(
                    selectedCve.detail.enriched_at,
                  )}
                </dd>
              </div>
            </dl>
          </section>

          <section
            className="cve-detail-panel"
            aria-labelledby="cve-references-title"
          >
            <h4 id="cve-references-title">
              References
            </h4>

            {selectedCve.detail
              .reference_links.length === 0 ? (
                <p>No reference links available.</p>
              ) : (
                <ul className="cve-reference-list">
                  {selectedCve.detail
                    .reference_links.map(
                      (reference, index) => (
                        <li key={reference}>
                          <a
                            href={reference}
                            target="_blank"
                            rel="noreferrer"
                          >
                            Open reference {index + 1}
                          </a>
                        </li>
                      ),
                    )}
                </ul>
              )}
          </section>

          <section
            className="cve-detail-panel"
            aria-labelledby="cve-evidence-title"
          >
            <header>
              <h4 id="cve-evidence-title">
                Supporting articles
              </h4>
              <span>
                {
                  selectedCve.evidence
                    .supporting_article_count
                } local mention
                {
                  selectedCve.evidence
                    .supporting_article_count === 1
                    ? ''
                    : 's'
                }
              </span>
            </header>

            {selectedCve.evidence
              .articles.length === 0 ? (
                <p>
                  No stored article currently
                  references this CVE.
                </p>
              ) : (
                <div className="cve-article-list">
                  {selectedCve.evidence
                    .articles.map((article) => (
                      <article
                        className="cve-article-card"
                        key={article.article_id}
                      >
                        <header>
                          <span>
                            {article.severity
                              ?? 'Unknown severity'}
                          </span>

                          <span>
                            {article.confidence_score
                              === null
                              ? 'Confidence unavailable'
                              : (
                                `${Math.round(
                                  article.confidence_score
                                  * 100,
                                )}% confidence`
                              )}
                          </span>
                        </header>

                        <h5>{article.title}</h5>

                        <p>
                          {article.source}
                          {' · '}
                          {formatDate(
                            article.published,
                          )}
                        </p>

                        <div>
                          <Link
                            to={
                              `/articles/${article.article_id}`
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
                    ))}
                </div>
              )}
          </section>
        </div>
      )}
    </section>
  )
}

export default CveIntelligencePanel