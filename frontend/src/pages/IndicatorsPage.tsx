import {
  useState,
} from 'react'
import type {
  FormEvent,
} from 'react'
import {
  Link,
} from 'react-router-dom'
import {
  getIndicatorCorrelation,
  getIndicatorScoring,
} from '../api/client'
import type {
  IndicatorCorrelationResponse,
  IndicatorScoringResponse,
} from '../api/types'
import './IndicatorsPage.css'

interface IndicatorInvestigationData {
  correlation: IndicatorCorrelationResponse
  scoring: IndicatorScoringResponse
}

const relatedEntityGroups = [
  {
    key: 'cves',
    label: 'CVEs',
  },
  {
    key: 'malware',
    label: 'Malware',
  },
  {
    key: 'mitre_techniques',
    label: 'MITRE techniques',
  },
  {
    key: 'apt_groups',
    label: 'APT groups',
  },
  {
    key: 'targeted_sectors',
    label: 'Targeted sectors',
  },
  {
    key: 'affected_technologies',
    label: 'Affected technologies',
  },
] as const

export function IndicatorsPage() {
  const [indicator, setIndicator] = useState('')
  const [includeOtx, setIncludeOtx] =
    useState(false)
  const [data, setData] =
    useState<IndicatorInvestigationData | null>(
      null,
    )
  const [loading, setLoading] = useState(false)
  const [error, setError] =
    useState<string | null>(null)

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const normalizedIndicator = indicator.trim()

    if (!normalizedIndicator) {
      setError('Indicator value is required.')
      return
    }

    setLoading(true)
    setError(null)
    setData(null)

    try {
      const [correlation, scoring] =
        await Promise.all([
          getIndicatorCorrelation({
            indicator: normalizedIndicator,
            includeOtx,
          }),
          getIndicatorScoring({
            indicator: normalizedIndicator,
            includeOtx,
          }),
        ])

      setData({
        correlation,
        scoring,
      })
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Indicator investigation failed.',
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="indicators-page">
      <header className="indicator-page-heading">
        <p>Indicator intelligence</p>
        <h2>Investigate an IOC</h2>
        <span>
          Correlate local evidence and optionally
          enrich the indicator with AlienVault OTX.
        </span>
      </header>

      <form
        className="indicator-search"
        aria-label="Indicator investigation"
        onSubmit={handleSubmit}
      >
        <label htmlFor="indicator-value">
          Indicator value
        </label>

        <input
          id="indicator-value"
          type="search"
          value={indicator}
          placeholder="IP, domain, URL or file hash"
          onChange={(event) => {
            setIndicator(event.target.value)
          }}
        />

        <label>
          <input
            type="checkbox"
            checked={includeOtx}
            onChange={(event) => {
              setIncludeOtx(event.target.checked)
            }}
          />
          Include OTX intelligence
        </label>

        <button
          type="submit"
          disabled={loading}
        >
          {loading
            ? 'Investigating...'
            : 'Investigate indicator'}
        </button>
      </form>

      {error && (
        <div
          className="indicator-error"
          role="alert"
        >
          {error}
        </div>
      )}
      {data && (
        <div className="indicator-results">
          <header className="indicator-result-heading">
            <p>{data.correlation.indicator_type}</p>
            <h3>{data.correlation.indicator}</h3>
          </header>

          <section
            className="indicator-assessment" 
            aria-label="Indicator assessment"
            >
            <div>
              <span>Threat score</span>
              <strong>
                {data.scoring.threat.threat_score}
              </strong>
              <small>
                {data.scoring.threat.threat_level}
              </small>
            </div>

            <div>
              <span>Confidence score</span>
              <strong>
                {
                  data.scoring.confidence
                    .confidence_score
                }
              </strong>
              <small>
                {
                  data.scoring.confidence
                    .confidence_level
                }
              </small>
            </div>

            <div>
              <span>Priority</span>
              <strong>
                {data.scoring.priority.priority_code}
              </strong>
              <small>
                {data.scoring.priority.priority_label}
              </small>
            </div>

            <div>
              <span>Recommended action</span>
              <strong>
                {
                  data.scoring.priority
                    .recommended_action
                }
              </strong>
            </div>
          </section>

          <section
            className="indicator-panel"
            aria-label="Local sightings"
          >
            <h4>Local sightings</h4>

            {data.correlation
              .supporting_article_count === 0 ? (
                <p>No local article sightings</p>
              ) : (
                <>
                  <p>
                    {
                      data.correlation
                        .supporting_article_count
                    } supporting article
                    {
                      data.correlation
                        .supporting_article_count === 1
                        ? ''
                        : 's'
                    }
                  </p>

                  <div className="indicator-articles">
                    {data.correlation
                      .supporting_articles.map(
                        (article) => (
                          <article
                            className="indicator-article-card"
                            key={article.article_id}
                          >
                            <header>
                              <span>
                                {
                                  article.severity
                                  ?? 'Unknown severity'
                                }
                              </span>

                              <span>
                                {
                                  article.confidence_score
                                  === null
                                    ? 'Confidence unavailable'
                                    : (
                                      `${Math.round(
                                        article.confidence_score
                                        * 100,
                                      )}% confidence`
                                    )
                                }
                              </span>
                            </header>

                            <h5>{article.title}</h5>

                            <p>
                              This indicator was extracted
                              from the stored analysis of
                              this article.
                            </p>

                            <div className="indicator-article-links">
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
                </>
              )}
          </section>
          <section
            className="indicator-panel"
            aria-label="Related intelligence"
          >
            <h4>Related intelligence</h4>

            <div className="indicator-related-entities">
              {relatedEntityGroups.every(
                ({ key }) => (
                  data.correlation.related_entities[key]
                    .length === 0
                ),
              ) && (
                <p>No related internal intelligence</p>
              )}
              {relatedEntityGroups.map(
                ({ key, label }) => {
                  const entities =
                    data.correlation
                      .related_entities[key]

                  if (entities.length === 0) {
                    return null
                  }

                  return (
                    <div
                      className="indicator-entity-group"
                      key={key}
                    >
                      <h5>{label}</h5>

                      <div className="indicator-entity-values">
                        {entities.map((entity) => (
                          <span key={entity.value}>
                            {entity.value}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                },
              )}
            </div>
          </section>

          <section
            className="indicator-panel"
            aria-label="OTX intelligence"
          >
            <h4>OTX intelligence</h4>

            {data.correlation.otx_enrichment ? (
              <>
                <strong>
                  {
                    data.correlation.otx_enrichment
                      .pulse_count
                  } OTX pulses
                </strong>
                <div className="indicator-otx-details">
                  {data.correlation.otx_enrichment
                    .country && (
                    <div>
                      <span>Location</span>
                      <strong>
                        {
                          data.correlation
                            .otx_enrichment.country
                        }
                        {
                          data.correlation
                            .otx_enrichment.country_code
                            ? (
                              ` (${data.correlation
                                .otx_enrichment
                                .country_code})`
                            )
                            : ''
                        }
                      </strong>
                    </div>
                  )}

                  {data.correlation.otx_enrichment
                    .asn && (
                    <div>
                      <span>Network</span>
                      <strong>
                        {
                          data.correlation
                            .otx_enrichment.asn
                        }
                      </strong>
                    </div>
                  )}

                  {data.correlation.otx_enrichment
                    .reputation !== null && (
                    <div>
                      <span>OTX reputation</span>
                      <strong>
                        {
                          data.correlation
                            .otx_enrichment.reputation
                        }
                      </strong>
                    </div>
                  )}
                </div>

                {data.correlation.otx_enrichment
                  .validation.map((validation, index) => (
                    <p key={
                      `${validation.source}-${validation.name}-${index}`
                    }>
                      {validation.message}
                    </p>
                  ))}
              </>
            ) : (
              <p>OTX intelligence not requested</p>
            )}
          </section>

          {data.scoring.warnings.length > 0 && (
            <section
              className="indicator-warning"
              aria-label="Scoring warnings"
              role="alert"
            >
              <h4>Scoring warnings</h4>

              {data.scoring.warnings.map(
                (warning,index) => (
                  <p key={
                    `${warning.source}-${warning.message}-${index}`
                  }>
                    {warning.message}
                  </p>
                ),
              )}
            </section>
          )}
        </div>
      )}
    </section>
  )
}

export default IndicatorsPage