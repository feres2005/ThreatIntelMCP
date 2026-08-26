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
  { key: 'cves', label: 'CVEs' },
  { key: 'malware', label: 'Malware' },
  {
    key: 'mitre_techniques',
    label: 'MITRE techniques',
  },
  { key: 'apt_groups', label: 'APT groups' },
  {
    key: 'targeted_sectors',
    label: 'Targeted sectors',
  },
  {
    key: 'affected_technologies',
    label: 'Affected technologies',
  },
] as const

function formatDate(value: string | null) {
  if (!value) {
    return 'Unavailable'
  }

  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

export function IndicatorsPage() {
  const [indicator, setIndicator] = useState('')
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
            includeOtx: true,
            includeVirusTotal: true,
          }),
          getIndicatorScoring({
            indicator: normalizedIndicator,
            includeOtx: true,
            includeVirusTotal: true,
          }),
        ])

      setData({ correlation, scoring })
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

  const hasRelatedEntities = data
    ? relatedEntityGroups.some(
      ({ key }) => (
        data.correlation.related_entities[key]
          .length > 0
      ),
    )
    : false

  return (
    <section className="indicators-page">
      <header className="indicator-page-heading">
        <p>Multi-source IOC intelligence</p>
        <h2>Investigate an indicator</h2>
        <span>
          Retrieve VirusTotal and AlienVault OTX
          intelligence first, then use locally stored
          articles as supporting context.
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
        <button
          type="submit"
          disabled={loading}
        >
          {loading
            ? 'Gathering intelligence...'
            : 'Investigate indicator'}
        </button>
        <div
          className="indicator-enabled-sources"
          aria-label="Intelligence sources included"
        >
          <span>VirusTotal enabled</span>
          <span>AlienVault OTX enabled</span>
        </div>
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
            className="indicator-primary-intelligence"
            aria-labelledby="primary-intelligence-title"
          >
            <header>
              <div>
                <p>External threat intelligence</p>
                <h4 id="primary-intelligence-title">
                  Primary intelligence sources
                </h4>
              </div>
              <span>
                Vendor detections and community
                intelligence drive the assessment.
              </span>
            </header>

            <div className="indicator-source-grid">
              <article
                className="indicator-source-card virustotal-card"
                aria-label="VirusTotal intelligence"
              >
                <header>
                  <div>
                    <p>Security vendor consensus</p>
                    <h5>VirusTotal</h5>
                  </div>
                  {data.correlation
                    .virustotal_enrichment && (
                    <span>
                      {
                        data.correlation
                          .virustotal_enrichment
                          .cache_status
                      }
                    </span>
                  )}
                </header>

                {!data.correlation
                  .virustotal_enrichment ? (
                    <p className="indicator-empty-source">
                      VirusTotal intelligence is
                      unavailable.
                    </p>
                  ) : !data.correlation
                    .virustotal_enrichment
                    .report_available ? (
                      <>
                        <div className="indicator-no-report">
                          No VirusTotal report is currently
                          available for this indicator.
                        </div>
                        <small>
                          Checked{' '}
                          {formatDate(
                            data.correlation
                              .virustotal_enrichment
                              .last_checked,
                          )}
                        </small>
                      </>
                    ) : (
                      <>
                        <div
                          className="virustotal-detection-ratio"
                          aria-label="VirusTotal detection ratio"
                        >
                          <strong>
                            {
                              data.correlation
                                .virustotal_enrichment
                                .malicious_count
                            }
                            {' / '}
                            {
                              data.correlation
                                .virustotal_enrichment
                                .total_engine_count
                            }
                          </strong>
                          <span>
                            security vendors flagged this
                            indicator as malicious
                          </span>
                        </div>

                        <dl className="indicator-source-metrics">
                          <div>
                            <dt>Malicious</dt>
                            <dd>
                              {
                                data.correlation
                                  .virustotal_enrichment
                                  .malicious_count
                              }
                            </dd>
                          </div>
                          <div>
                            <dt>Suspicious</dt>
                            <dd>
                              {
                                data.correlation
                                  .virustotal_enrichment
                                  .suspicious_count
                              }
                            </dd>
                          </div>
                          <div>
                            <dt>Undetected</dt>
                            <dd>
                              {
                                data.correlation
                                  .virustotal_enrichment
                                  .undetected_count
                              }
                            </dd>
                          </div>
                          <div>
                            <dt>Reputation</dt>
                            <dd>
                              {
                                data.correlation
                                  .virustotal_enrichment
                                  .reputation
                                ?? 'Unavailable'
                              }
                            </dd>
                          </div>
                        </dl>

                        {data.correlation
                          .virustotal_enrichment
                          .detections.length > 0 && (
                          <div className="virustotal-detections">
                            <h6>Detection examples</h6>
                            <ul>
                              {data.correlation
                                .virustotal_enrichment
                                .detections.slice(0, 6)
                                .map((detection) => (
                                  <li key={
                                    `${detection.engine_name}-${detection.category}`
                                  }>
                                    <strong>
                                      {detection.engine_name}
                                    </strong>
                                    <span>
                                      {detection.result
                                        ?? detection.category}
                                    </span>
                                  </li>
                                ))}
                            </ul>
                          </div>
                        )}

                        <div className="indicator-source-footer">
                          <span>
                            Last analysis:{' '}
                            {formatDate(
                              data.correlation
                                .virustotal_enrichment
                                .last_analysis_date,
                            )}
                          </span>
                          {data.correlation
                            .virustotal_enrichment
                            .permalink && (
                            <a
                              href={
                                data.correlation
                                  .virustotal_enrichment
                                  .permalink
                              }
                              target="_blank"
                              rel="noreferrer"
                            >
                              Open VirusTotal report
                            </a>
                          )}
                        </div>

                        {data.correlation
                          .virustotal_enrichment
                          .is_stale && (
                          <p className="indicator-source-caveat">
                            VirusTotal is temporarily
                            unavailable. Showing the latest
                            cached report.
                          </p>
                        )}

                        <p className="indicator-source-caveat">
                          A vendor detection is evidence,
                          not automatic proof. Validate the
                          indicator in its operational
                          context.
                        </p>
                      </>
                    )}
              </article>

              <article
                className="indicator-source-card otx-card"
                aria-label="OTX intelligence"
              >
                <header>
                  <div>
                    <p>Community threat intelligence</p>
                    <h5>AlienVault OTX</h5>
                  </div>
                </header>

                {data.correlation.otx_enrichment ? (
                  <>
                    <div className="otx-pulse-count">
                      <strong>
                        {
                          data.correlation.otx_enrichment
                            .pulse_count
                        }
                      </strong>
                      <span>OTX community pulses</span>
                    </div>

                    <dl className="indicator-source-metrics">
                      <div>
                        <dt>Reputation</dt>
                        <dd>
                          {
                            data.correlation.otx_enrichment
                              .reputation
                            ?? 'Unavailable'
                          }
                        </dd>
                      </div>
                      <div>
                        <dt>Location</dt>
                        <dd>
                          {
                            data.correlation.otx_enrichment
                              .country
                            ?? 'Unavailable'
                          }
                          {data.correlation.otx_enrichment
                            .country_code
                            ? ` (${data.correlation.otx_enrichment.country_code})`
                            : ''}
                        </dd>
                      </div>
                      <div>
                        <dt>Network</dt>
                        <dd>
                          {
                            data.correlation.otx_enrichment
                              .asn
                            ?? 'Unavailable'
                          }
                        </dd>
                      </div>
                      <div>
                        <dt>Last checked</dt>
                        <dd>
                          {formatDate(
                            data.correlation.otx_enrichment
                              .last_checked,
                          )}
                        </dd>
                      </div>
                    </dl>

                    {data.correlation.otx_enrichment
                      .validation.length > 0 && (
                      <div className="otx-validations">
                        <h6>Validation context</h6>
                        {data.correlation.otx_enrichment
                          .validation.map(
                            (validation, index) => (
                              <p key={
                                `${validation.source}-${validation.name}-${index}`
                              }>
                                {validation.message}
                              </p>
                            ),
                          )}
                      </div>
                    )}

                    <p className="indicator-source-caveat">
                      Pulse references provide community
                      context; they do not independently
                      confirm malicious activity.
                    </p>
                  </>
                ) : (
                  <p className="indicator-empty-source">
                    OTX intelligence is unavailable.
                  </p>
                )}
              </article>
            </div>
          </section>

          <section
            className="indicator-assessment"
            aria-label="Consolidated indicator assessment"
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

          {data.scoring.warnings.length > 0 && (
            <section
              className="indicator-warning"
              aria-label="Scoring warnings"
              role="alert"
            >
              <h4>Assessment warnings</h4>
              {data.scoring.warnings.map(
                (warning, index) => (
                  <p key={
                    `${warning.source}-${warning.message}-${index}`
                  }>
                    {warning.message}
                  </p>
                ),
              )}
            </section>
          )}

          <section
            className="indicator-secondary-context"
            aria-labelledby="secondary-context-title"
          >
            <header>
              <div>
                <p>Internal corroboration</p>
                <h4 id="secondary-context-title">
                  Local supporting context
                </h4>
              </div>
              <span>
                Article evidence strengthens the external
                findings when a local match exists.
              </span>
            </header>

            <section
              className="indicator-panel"
              aria-label="Local sightings"
            >
              <h5>Local article sightings</h5>

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
                                  {article.severity
                                    ?? 'Unknown severity'}
                                </span>
                                <span>
                                  {article.confidence_score
                                    === null
                                    ? 'Confidence unavailable'
                                    : `${Math.round(
                                      article.confidence_score
                                      * 100,
                                    )}% confidence`}
                                </span>
                              </header>
                              <h6>{article.title}</h6>
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
              <h5>Related internal intelligence</h5>
              <div className="indicator-related-entities">
                {!hasRelatedEntities && (
                  <p>
                    No related internal intelligence
                  </p>
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
                        <h6>{label}</h6>
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
          </section>
        </div>
      )}
    </section>
  )
}

export default IndicatorsPage