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
  getMitreSupportingArticles,
  getMitreTechniqueDetails,
  searchMitreTechniques,
} from '../../api/client'
import type {
  MitreDomain,
  MitreSearchItem,
  MitreSupportingArticlesResponse,
  MitreTechniqueDetail,
} from '../../api/types'

const EXACT_TECHNIQUE_PATTERN =
  /^T\d{4}(?:\.\d{3})?$/i

interface SelectedTechnique {
  detail: MitreTechniqueDetail
  evidence: MitreSupportingArticlesResponse
}

const domainLabels: Record<
  MitreDomain,
  string
> = {
  'enterprise-attack': 'Enterprise',
  'mobile-attack': 'Mobile',
  'ics-attack': 'ICS',
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
    },
  ).format(date)
}

export function MitreIntelligencePanel() {
  const [query, setQuery] = useState('')
  const [domain, setDomain] =
    useState<MitreDomain | ''>('')
  const [includeInactive, setIncludeInactive] =
    useState(false)
  const [results, setResults] =
    useState<MitreSearchItem[] | null>(null)
  const [selectedTechnique, setSelectedTechnique] =
    useState<SelectedTechnique | null>(null)
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

  async function loadTechnique(
    techniqueId: string,
  ): Promise<void> {
    const controller = beginRequest()

    setLoading(true)
    setError(null)
    setSelectedTechnique(null)

    try {
      const [detail, evidence] =
        await Promise.all([
          getMitreTechniqueDetails(
            techniqueId,
            controller.signal,
          ),
          getMitreSupportingArticles(
            techniqueId,
            20,
            controller.signal,
          ),
        ])

      if (!controller.signal.aborted) {
        setSelectedTechnique({
          detail,
          evidence,
        })
      }
    } catch (requestError) {
      if (!controller.signal.aborted) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : 'MITRE technique lookup failed.',
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
      setError(
        'MITRE search value is required.',
      )
      return
    }

    setError(null)
    setSelectedTechnique(null)

    if (
      EXACT_TECHNIQUE_PATTERN.test(
        normalizedQuery,
      )
    ) {
      setResults(null)

      await loadTechnique(
        normalizedQuery.toUpperCase(),
      )
      return
    }

    const controller = beginRequest()

    setLoading(true)
    setResults(null)

    try {
      const response =
        await searchMitreTechniques(
          {
            keyword: normalizedQuery,
            limit: 10,
            offset: 0,
            domain: domain || undefined,
            includeInactive,
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
            : 'MITRE technique search failed.',
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

  const detail = selectedTechnique?.detail
  const evidence = selectedTechnique?.evidence

  return (
    <section
      className="mitre-intelligence-panel"
      aria-labelledby="mitre-panel-title"
    >
      <header className="intelligence-section-heading">
        <p>Adversary behavior knowledge</p>
        <h2 id="mitre-panel-title">
          MITRE ATT&amp;CK Intelligence
        </h2>
        <span>
          Search techniques by identifier, name,
          description or supported platform.
        </span>
      </header>

      <form
        className="mitre-search"
        aria-label="MITRE technique search"
        onSubmit={handleSubmit}
      >
        <label htmlFor="mitre-search-value">
          Technique identifier or keyword
        </label>

        <input
          id="mitre-search-value"
          type="search"
          value={query}
          placeholder="Example: T1566.002, PowerShell or Windows"
          onChange={(event) => {
            setQuery(event.target.value)
          }}
        />

        <label htmlFor="mitre-domain">
          ATT&amp;CK domain
        </label>

        <select
          id="mitre-domain"
          value={domain}
          onChange={(event) => {
            setDomain(
              event.target.value as (
                MitreDomain | ''
              ),
            )
          }}
        >
          <option value="">
            All domains
          </option>
          <option value="enterprise-attack">
            Enterprise
          </option>
          <option value="mobile-attack">
            Mobile
          </option>
          <option value="ics-attack">
            ICS
          </option>
        </select>

        <label className="mitre-inactive-option">
          <input
            type="checkbox"
            checked={includeInactive}
            onChange={(event) => {
              setIncludeInactive(
                event.target.checked,
              )
            }}
          />
          Include revoked and deprecated techniques
        </label>

        <button
          type="submit"
          disabled={loading}
        >
          {loading
            ? 'Searching...'
            : 'Search ATT&CK'}
        </button>
      </form>

      {loading && (
        <div
          className="intelligence-status"
          role="status"
        >
          Loading MITRE intelligence...
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
          className="mitre-search-results"
          aria-labelledby="mitre-results-title"
        >
          <header>
            <p>Technique catalogue</p>
            <h3 id="mitre-results-title">
              {results.length} technique
              {results.length === 1 ? '' : 's'}
            </h3>
          </header>

          {results.length === 0 ? (
            <p>
              No MITRE techniques matched this
              search and filter combination.
            </p>
          ) : (
            <div className="mitre-result-list">
              {results.map((technique) => (
                <article
                  className="mitre-result-card"
                  key={technique.technique_id}
                >
                  <header>
                    <strong>
                      {technique.technique_id}
                    </strong>

                    <span>
                      {
                        domainLabels[
                          technique.domain
                        ]
                      }
                    </span>
                  </header>

                  <h3>{technique.name}</h3>

                  <div>
                    <span>
                      {technique.is_subtechnique
                        ? 'Sub-technique'
                        : 'Technique'}
                    </span>

                    <span>
                      Version{' '}
                      {technique.version
                        ?? 'unavailable'}
                    </span>
                  </div>

                  {(technique.revoked
                    || technique.deprecated) && (
                    <p>
                      Historical inactive technique
                    </p>
                  )}

                  <button
                    type="button"
                    onClick={() => {
                      void loadTechnique(
                        technique.technique_id,
                      )
                    }}
                  >
                    View {technique.technique_id}
                  </button>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {detail && evidence && (
        <section
          className="mitre-detail"
          aria-label="MITRE technique details"
        >
          <header className="mitre-detail-heading">
            <div>
              <p>{detail.technique_id}</p>
              <h3>{detail.name}</h3>
              <span>
                {domainLabels[detail.domain]}
                {' · '}
                {detail.is_subtechnique
                  ? 'Sub-technique'
                  : 'Technique'}
              </span>
            </div>

            <div>
              <span>Version</span>
              <strong>
                {detail.version ?? 'Unavailable'}
              </strong>
            </div>
          </header>

          <section className="mitre-detail-panel">
            <h4>Description</h4>
            <p>
              {detail.description
                ?? 'Description unavailable.'}
            </p>

            <dl className="mitre-metadata">
              <div>
                <dt>Created</dt>
                <dd>
                  {formatDate(detail.created)}
                </dd>
              </div>

              <div>
                <dt>Modified</dt>
                <dd>
                  {formatDate(detail.modified)}
                </dd>
              </div>

              <div>
                <dt>STIX identifier</dt>
                <dd>{detail.stix_id}</dd>
              </div>
            </dl>
          </section>

          <section className="mitre-detail-panel">
            <h4>Platforms</h4>

            {!detail.platforms
              || detail.platforms.length === 0 ? (
                <p>No platforms specified.</p>
              ) : (
                <div className="mitre-value-list">
                  {detail.platforms.map(
                    (platform) => (
                      <span key={platform}>
                        {platform}
                      </span>
                    ),
                  )}
                </div>
              )}
          </section>

          <section className="mitre-detail-panel">
            <h4>Kill-chain phases</h4>

            {!detail.kill_chain_phases
              || detail.kill_chain_phases
                .length === 0 ? (
                <p>
                  No kill-chain phases specified.
                </p>
              ) : (
                <div className="mitre-phase-list">
                  {detail.kill_chain_phases.map(
                    (phase) => (
                      <div
                        key={
                          `${phase.kill_chain_name}-`
                          + phase.phase_name
                        }
                      >
                        <span>
                          {phase.kill_chain_name}
                        </span>
                        <strong>
                          {phase.phase_name}
                        </strong>
                      </div>
                    ),
                  )}
                </div>
              )}
          </section>

          <section className="mitre-detail-panel">
            <h4>References</h4>

            {!detail.reference_links
              || detail.reference_links
                .length === 0 ? (
                <p>No references available.</p>
              ) : (
                <ul className="mitre-reference-list">
                  {detail.reference_links.map(
                    (reference, index) => (
                      <li
                        key={
                          `${reference.source_name}-`
                          + index
                        }
                      >
                        {reference.url ? (
                          <a
                            href={reference.url}
                            target="_blank"
                            rel="noreferrer"
                          >
                            {reference.source_name}
                          </a>
                        ) : (
                          <span>
                            {reference.source_name}
                          </span>
                        )}
                      </li>
                    ),
                  )}
                </ul>
              )}
          </section>

          <section className="mitre-detail-panel mitre-evidence">
            <header>
              <h4>Supporting articles</h4>
              <span>
                {evidence.supporting_article_count}
                {' '}
                local mention
                {
                  evidence.supporting_article_count
                  === 1
                    ? ''
                    : 's'
                }
              </span>
            </header>

            {evidence.articles.length === 0 ? (
              <p>
                No stored article currently
                references this technique.
              </p>
            ) : (
              <div className="mitre-article-list">
                {evidence.articles.map(
                  (article) => (
                    <article
                      className="mitre-article-card"
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
                  ),
                )}
              </div>
            )}
          </section>
        </section>
      )}
    </section>
  )
}

export default MitreIntelligencePanel