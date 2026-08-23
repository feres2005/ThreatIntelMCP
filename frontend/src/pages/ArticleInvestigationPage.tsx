import {
  ArrowLeft,
  ExternalLink,
} from 'lucide-react'
import {
  useEffect,
  useState,
} from 'react'
import {
  Link,
  useParams,
} from 'react-router-dom'

import {
  getArticleInvestigation,
  getArticleScoring,
} from '../api/client'
import type {
  ArticleInvestigationResponse,
  ArticleScoringResponse,
  ScoreComponent,
} from '../api/types'

import './ArticleInvestigationPage.css'

interface InvestigationData {
  investigation: ArticleInvestigationResponse
  scoring: ArticleScoringResponse
}

const dateFormatter = new Intl.DateTimeFormat(
  'en-US',
  {
    dateStyle: 'medium',
    timeStyle: 'short',
  },
)

function formatComponentName(
  value: string,
): string {
  return value
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) => (
      character.toUpperCase()
    ))
}

function EvidenceGroup({
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
    <div className="evidence-group">
      <h3>{label}</h3>
      <div>
        {values.map((value) => (
          <span key={value}>{value}</span>
        ))}
      </div>
    </div>
  )
}

function ScoreBreakdown({
  title,
  components,
}: {
  title: string
  components: Record<string, ScoreComponent>
}) {
  return (
    <article className="score-breakdown">
      <h3>{title}</h3>

      <div>
        {Object.entries(components).map(
          ([name, component]) => {
            const percentage =
              component.maximum_points > 0
                ? (
                    component.points
                    / component.maximum_points
                  ) * 100
                : 0

            return (
              <div
                className="score-component"
                key={name}
              >
                <div>
                  <span>
                    {formatComponentName(name)}
                  </span>
                  <strong>
                    {component.points}
                    {' / '}
                    {component.maximum_points}
                  </strong>
                </div>

                <div className="score-track">
                  <span
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(0, percentage),
                      )}%`,
                    }}
                  />
                </div>
              </div>
            )
          },
        )}
      </div>
    </article>
  )
}

function ArticleInvestigationPage() {
  const { articleId: articleIdParameter } =
    useParams()

  const articleId = Number(articleIdParameter)
  const hasValidArticleId = (
    Number.isInteger(articleId)
    && articleId > 0
)

  const [data, setData] =
    useState<InvestigationData | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (!hasValidArticleId) {
        return
}

    const controller = new AbortController()

    Promise.all([
      getArticleInvestigation(
        articleId,
        controller.signal,
      ),
      getArticleScoring(
        articleId,
        controller.signal,
      ),
    ])
      .then(([investigation, scoring]) => {
        setData({
          investigation,
          scoring,
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
  }, [articleId, hasValidArticleId])

  if (!hasValidArticleId || failed) {
    return (
      <section className="investigation-page">
        <div className="page-state" role="alert">
          <strong>
            Unable to build this investigation.
          </strong>
          <p>
            The article may not exist or the backend
            may be unavailable.
          </p>
          <Link to="/articles">
            Return to article search
          </Link>
        </div>
      </section>
    )
  }

  if (!data) {
    return (
      <section className="investigation-page">
        <div className="page-state" role="status">
          Building investigation…
        </div>
      </section>
    )
  }

  const { investigation, scoring } = data
  const { article } = investigation

  return (
    <section className="investigation-page">
      <Link
        className="back-link"
        to="/articles"
      >
        <ArrowLeft aria-hidden="true" />
        Back to article search
      </Link>

      <header className="investigation-heading">
        <div className="investigation-meta">
          <span
            className="severity-badge"
            data-severity={
              article.severity.toLowerCase()
            }
          >
            {article.severity}
          </span>

          {article.published && (
            <span>
              {dateFormatter.format(
                new Date(article.published),
              )}
            </span>
          )}
        </div>

        <h2>{article.title}</h2>
        <p>{article.summary}</p>

        <a
          href={article.link}
          target="_blank"
          rel="noreferrer"
        >
          Open source article
          <ExternalLink aria-hidden="true" />
        </a>
      </header>

      <div className="score-overview">
        <article aria-label="Threat score">
          <span>Threat score</span>
          <strong>
            {scoring.threat.threat_score}
          </strong>
          <small>
            {scoring.threat.threat_level}
          </small>
        </article>

        <article aria-label="Confidence score">
          <span>Confidence score</span>
          <strong>
            {scoring.confidence.confidence_score}
          </strong>
          <small>
            {scoring.confidence.confidence_level}
          </small>
        </article>

        <article className="priority-card">
          <span>Response priority</span>
          <strong>
            {scoring.priority.priority_code}
          </strong>
          <small>
            {scoring.priority.priority_label}
          </small>
        </article>

        <article className="action-card">
          <span>Recommended action</span>
          <strong>
            {scoring.priority.recommended_action}
          </strong>
        </article>
      </div>

      <div className="investigation-grid">
        <article className="investigation-panel">
          <header>
            <p>Extracted context</p>
            <h3>Threat evidence</h3>
          </header>

          <div className="evidence-groups">
            <EvidenceGroup
              label="Classifications"
              values={article.classification}
            />
            <EvidenceGroup
              label="APT groups"
              values={article.apt_groups}
            />
            <EvidenceGroup
              label="CVEs"
              values={article.cves}
            />
            <EvidenceGroup
              label="Malware"
              values={article.malware}
            />
            <EvidenceGroup
              label="Affected technologies"
              values={
                article.affected_technologies
              }
            />
            <EvidenceGroup
              label="Targeted sectors"
              values={article.targeted_sectors}
            />
          </div>
        </article>

        <article className="investigation-panel">
          <header>
            <p>ATT&CK mapping</p>
            <h3>MITRE techniques</h3>
          </header>

          <div className="mitre-list">
            {investigation.mitre_enrichment.map(
              (technique) => (
                <article key={technique.technique_id}>
                  <span>
                    {technique.technique_id}
                  </span>
                  <h3>
                    {technique.details?.name
                      ?? 'Enrichment unavailable'}
                  </h3>

                  {technique.details && (
                    <>
                      <p>
                        {technique.details.domain
                          .replaceAll('-', ' ')}
                      </p>
                      <div>
                        {technique.details.platforms
                          .slice(0, 5)
                          .map((platform) => (
                            <span key={platform}>
                              {platform}
                            </span>
                          ))}
                      </div>
                    </>
                  )}
                </article>
              ),
            )}
          </div>
        </article>
      </div>

      <div className="breakdown-grid">
        <ScoreBreakdown
          title="Threat score components"
          components={
            scoring.threat.components
          }
        />
        <ScoreBreakdown
          title="Confidence components"
          components={
            scoring.confidence.components
          }
        />
      </div>

      {scoring.warnings.length > 0 && (
        <aside
          className="warning-panel"
          aria-label="Scoring warnings"
        >
          <strong>Scoring warnings</strong>
          <ul>
            {scoring.warnings.map((warning) => (
              <li
                key={`${warning.source}-${warning.message}`}
              >
                {warning.message}
              </li>
            ))}
          </ul>
        </aside>
      )}
    </section>
  )
}

export default ArticleInvestigationPage
