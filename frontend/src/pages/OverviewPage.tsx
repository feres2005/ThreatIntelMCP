import {
  useEffect,
  useState,
} from 'react'

import {
  getHealth,
  getPipelineStatus,
} from '../api/client'
import type {
  HealthResponse,
  PipelineStatusResponse,
} from '../api/types'

import './OverviewPage.css'

interface OverviewData {
  health: HealthResponse
  pipeline: PipelineStatusResponse
}

const numberFormatter = new Intl.NumberFormat(
  'en-US',
)

function CoverageBar({
  label,
  value,
}: {
  label: string
  value: number
}) {
  const boundedValue = Math.min(
    100,
    Math.max(0, value),
  )

  return (
    <div className="coverage-item">
      <div className="coverage-label">
        <span>{label}</span>
        <strong>{value.toFixed(1)}%</strong>
      </div>
      <div
        className="coverage-track"
        role="progressbar"
        aria-label={`${label} coverage`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
      >
        <span
          style={{
            width: `${boundedValue}%`,
          }}
        />
      </div>
    </div>
  )
}

function OverviewPage() {
  const [data, setData] =
    useState<OverviewData | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    const controller = new AbortController()

    Promise.all([
      getHealth(controller.signal),
      getPipelineStatus(controller.signal),
    ])
      .then(([health, pipeline]) => {
        setData({
          health,
          pipeline,
        })
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setFailed(true)
        }
      })

    return () => {
      controller.abort()
    }
  }, [])

  if (failed) {
    return (
      <section className="overview-page">
        <div className="page-state" role="alert">
          <strong>
            Unable to load operational data.
          </strong>
          <p>
            Confirm that the FastAPI backend and
            PostgreSQL are available.
          </p>
        </div>
      </section>
    )
  }

  if (!data) {
    return (
      <section className="overview-page">
        <div className="page-state" role="status">
          Loading operational data…
        </div>
      </section>
    )
  }

  const { health, pipeline } = data

  const metrics = [
    {
      label: 'Total articles',
      value: pipeline.counts.total_articles,
    },
    {
      label: 'Analyzed articles',
      value: pipeline.counts.analyzed_articles,
    },
    {
      label: 'Article embeddings',
      value: pipeline.counts.article_embeddings,
    },
    {
      label: 'Enriched CVEs',
      value: pipeline.counts.enriched_cves,
    },
    {
      label: 'MITRE techniques',
      value: pipeline.counts.mitre_techniques,
    },
    {
      label: 'GitHub advisories',
      value: pipeline.counts.github_advisories,
    },
  ]

  return (
    <section className="overview-page">
      <header className="page-heading">
        <div>
          <p>System status</p>
          <h2>Operational Overview</h2>
          <span>
            Live coverage and intelligence inventory
          </span>
        </div>

        <div className="health-badge">
          <span aria-hidden="true" />
          API {health.status}
        </div>
      </header>

      <div className="metrics-grid">
        {metrics.map((metric) => (
          <article
            key={metric.label}
            aria-label={metric.label}
            className="metric-card"
          >
            <span>{metric.label}</span>
            <strong>
              {numberFormatter.format(metric.value)}
            </strong>
          </article>
        ))}
      </div>

      <div className="overview-grid">
        <article className="overview-panel">
          <header>
            <div>
              <p>Processing state</p>
              <h3>Pipeline coverage</h3>
            </div>
            <span className="status-label">
              {pipeline.health_status.replaceAll(
                '_',
                ' ',
              )}
            </span>
          </header>

          <div className="coverage-list">
            <CoverageBar
              label="Processing"
              value={
                pipeline.coverage.processing_percent
              }
            />
            <CoverageBar
              label="Analysis"
              value={
                pipeline.coverage.analysis_percent
              }
            />
            <CoverageBar
              label="Embedding"
              value={
                pipeline.coverage.embedding_percent
              }
            />
          </div>
        </article>

        <article className="overview-panel">
          <header>
            <div>
              <p>Current backlog</p>
              <h3>Work pending</h3>
            </div>
          </header>

          <dl className="backlog-list">
            <div>
              <dt>Article processing</dt>
              <dd>
                {numberFormatter.format(
                  pipeline.work_pending
                    .article_processing,
                )}
              </dd>
            </div>
            <div>
              <dt>Embedding indexing</dt>
              <dd>
                {numberFormatter.format(
                  pipeline.work_pending
                    .embedding_indexing,
                )}
              </dd>
            </div>
          </dl>
        </article>
      </div>

      {pipeline.warnings.length > 0 && (
        <aside
          className="warning-panel"
          aria-label="Pipeline warnings"
        >
          <strong>Attention required</strong>
          <ul>
            {pipeline.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </aside>
      )}
    </section>
  )
}

export default OverviewPage