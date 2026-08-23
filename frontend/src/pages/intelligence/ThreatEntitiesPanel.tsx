import {
  useState,
  type FormEvent,
} from 'react'
import { Link } from 'react-router-dom'

import {
  getThreatEntityEvidence,
  searchThreatEntities,
} from '../../api/client'
import type {
  ThreatEntityEvidenceResponse,
  ThreatEntitySearchItem,
  ThreatEntityType,
} from '../../api/types'

const ENTITY_OPTIONS: Array<{
  value: ThreatEntityType
  label: string
}> = [
  {
    value: 'malware',
    label: 'Malware',
  },
  {
    value: 'apt_group',
    label: 'APT group',
  },
  {
    value: 'targeted_sector',
    label: 'Targeted sector',
  },
  {
    value: 'affected_technology',
    label: 'Affected technology',
  },
]

function formatEntityType(
  entityType: ThreatEntityType,
): string {
  return (
    ENTITY_OPTIONS.find(
      (option) => option.value === entityType,
    )?.label ?? entityType
  )
}

function formatDate(value: string | null): string {
  if (!value) {
    return 'Date unavailable'
  }

  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function EntityValues({
  label,
  values,
}: {
  label: string
  values: string[]
}) {
  if (values.length === 0) {
    return null
  }

  return (
    <div className="threat-entity-values">
      <strong>{label}</strong>
      <div>
        {values.map((value) => (
          <span key={value}>{value}</span>
        ))}
      </div>
    </div>
  )
}

export function ThreatEntitiesPanel() {
  const [entityType, setEntityType] =
    useState<ThreatEntityType>('malware')
  const [keyword, setKeyword] = useState('')
  const [results, setResults] =
    useState<ThreatEntitySearchItem[]>([])
  const [evidence, setEvidence] =
    useState<ThreatEntityEvidenceResponse | null>(
      null,
    )
  const [hasSearched, setHasSearched] =
    useState(false)
  const [searching, setSearching] =
    useState(false)
  const [loadingEvidence, setLoadingEvidence] =
    useState(false)
  const [error, setError] =
    useState<string | null>(null)

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()

    const normalizedKeyword = keyword.trim()

    if (!normalizedKeyword) {
      return
    }

    setSearching(true)
    setError(null)
    setEvidence(null)

    try {
      const response = await searchThreatEntities({
        entityType,
        keyword: normalizedKeyword,
        limit: 10,
      })

      setResults(response.results)
      setHasSearched(true)
    } catch (caughtError) {
      setResults([])
      setHasSearched(true)
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Unable to search threat entities.',
      )
    } finally {
      setSearching(false)
    }
  }

  async function loadEvidence(
    result: ThreatEntitySearchItem,
  ): Promise<void> {
    setLoadingEvidence(true)
    setError(null)

    try {
      const response =
        await getThreatEntityEvidence({
          entityType,
          value: result.value,
          limit: 20,
        })

      setEvidence(response)
    } catch (caughtError) {
      setEvidence(null)
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Unable to load entity evidence.',
      )
    } finally {
      setLoadingEvidence(false)
    }
  }

  return (
    <section
      className="threat-entities-panel"
      aria-labelledby="entities-panel-title"
    >
      <header className="intelligence-section-heading">
        <p>Article-derived threat knowledge</p>
        <h2 id="entities-panel-title">
          Threat Entities
        </h2>
        <span>
          Search malware, APT groups, targeted
          sectors and affected technologies
          extracted from stored article analyses.
        </span>
      </header>

      <form
        className="threat-entity-search"
        aria-label="Threat entity search"
        onSubmit={handleSubmit}
      >
        <label htmlFor="threat-entity-type">
          Entity category
        </label>
        <select
          id="threat-entity-type"
          value={entityType}
          onChange={(event) => {
            setEntityType(
              event.target.value as
                ThreatEntityType,
            )
            setResults([])
            setEvidence(null)
            setHasSearched(false)
            setError(null)
          }}
        >
          {ENTITY_OPTIONS.map((option) => (
            <option
              key={option.value}
              value={option.value}
            >
              {option.label}
            </option>
          ))}
        </select>

        <label htmlFor="threat-entity-keyword">
          Entity name or keyword
        </label>
        <input
          id="threat-entity-keyword"
          type="search"
          value={keyword}
          placeholder={
            'Example: Qilin, Government '
            + 'or Microsoft 365'
          }
          onChange={(event) => {
            setKeyword(event.target.value)
          }}
        />

        <button
          type="submit"
          disabled={
            searching || !keyword.trim()
          }
        >
          {searching
            ? 'Searching…'
            : 'Search threat entities'}
        </button>
      </form>

      <p className="threat-entity-source-note">
        Results are derived from locally stored
        article analysis. No external intelligence
        request is made by this search.
      </p>

      {error && (
        <div
          className="intelligence-error"
          role="alert"
        >
          {error}
        </div>
      )}

      {hasSearched && results.length === 0 && (
        <div className="threat-entity-empty">
          No matching threat entities were found.
        </div>
      )}

      {results.length > 0 && (
        <section
          className="threat-entity-results"
          aria-labelledby="entity-results-title"
        >
          <header>
            <p>
              {formatEntityType(entityType)}
            </p>
            <h3 id="entity-results-title">
              {results.length}{' '}
              {results.length === 1
                ? 'entity'
                : 'entities'}
            </h3>
          </header>

          <div className="threat-entity-result-list">
            {results.map((result) => (
              <article
                key={result.value.toLowerCase()}
                className="threat-entity-result-card"
              >
                <header>
                  <span>
                    {formatEntityType(entityType)}
                  </span>
                  <strong>
                    {result.supporting_article_count}{' '}
                    {result.supporting_article_count
                      === 1
                      ? 'article'
                      : 'articles'}
                  </strong>
                </header>

                <h4>{result.value}</h4>

                <p>
                  Latest local sighting:{' '}
                  {formatDate(result.latest_seen)}
                </p>

                <button
                  type="button"
                  disabled={loadingEvidence}
                  onClick={() => {
                    void loadEvidence(result)
                  }}
                >
                  Investigate {result.value}
                </button>
              </article>
            ))}
          </div>
        </section>
      )}

      {evidence && (
        <section
          className="threat-entity-evidence"
          aria-labelledby="entity-evidence-title"
        >
          <header>
            <div>
              <p>
                {formatEntityType(
                  evidence.entity_type,
                )}
              </p>
              <h3 id="entity-evidence-title">
                {evidence.value}
              </h3>
            </div>

            <div>
              <strong>
                {evidence.supporting_article_count}
              </strong>
              <span>
                supporting{' '}
                {evidence.supporting_article_count
                  === 1
                  ? 'article'
                  : 'articles'}
              </span>
            </div>
          </header>

          {evidence.articles.length === 0 ? (
            <div className="threat-entity-empty">
              No supporting articles were found.
            </div>
          ) : (
            <div className="threat-entity-article-list">
              {evidence.articles.map((article) => (
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
                          article.confidence_score
                            * 100,
                        )}% confidence`}
                    </span>
                  </header>

                  <h4>{article.title}</h4>

                  <p className="threat-entity-article-meta">
                    {article.source
                      ?? 'Unknown source'}
                    {' · '}
                    {formatDate(article.published)}
                  </p>

                  <p>
                    {article.summary
                      ?? 'Summary unavailable.'}
                  </p>

                  <div className="threat-entity-relations">
                    <EntityValues
                      label="CVEs"
                      values={article.cves}
                    />
                    <EntityValues
                      label="Malware"
                      values={article.malware}
                    />
                    <EntityValues
                      label="MITRE techniques"
                      values={
                        article.mitre_techniques
                      }
                    />
                    <EntityValues
                      label="APT groups"
                      values={article.apt_groups}
                    />
                    <EntityValues
                      label="Targeted sectors"
                      values={
                        article.targeted_sectors
                      }
                    />
                    <EntityValues
                      label="Affected technologies"
                      values={
                        article
                          .affected_technologies
                      }
                    />
                  </div>

                  <footer>
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
                  </footer>
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </section>
  )
}

export default ThreatEntitiesPanel