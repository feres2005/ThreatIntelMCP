import {
  ArrowDownRight,
  ArrowUpRight,
  ExternalLink,
  Minus,
} from 'lucide-react'
import {
  useEffect,
  useState,
} from 'react'

import { getEmergingTopics } from '../api/client'
import type {
  EmergingTopic,
  EmergingTopicsResponse,
  TopicTrend,
} from '../api/types'

import './TopicsPage.css'

const numberFormatter = new Intl.NumberFormat(
  'en-US',
)

const dateFormatter = new Intl.DateTimeFormat(
  'en-US',
  {
    dateStyle: 'medium',
    timeStyle: 'short',
  },
)

const trendLabels: Record<TopicTrend, string> = {
  rising: 'Rising',
  stable: 'Stable',
  declining: 'Declining',
}

function TopicCard({
  topic,
}: {
  topic: EmergingTopic
}) {
  const TrendIcon =
    topic.trend === 'rising'
      ? ArrowUpRight
      : topic.trend === 'declining'
        ? ArrowDownRight
        : Minus

  const evidence = [
    ...new Set([
      ...topic.cves,
      ...topic.classifications,
      ...topic.severities,
      ...topic.malware,
      ...topic.mitre_techniques,
      ...topic.apt_groups,
      ...topic.targeted_sectors,
      ...topic.affected_technologies,
    ]),
  ].slice(0, 8)

  const score = Math.round(
    topic.trend_score * 100,
  )

  return (
    <article className="topic-card">
      <header className="topic-card-heading">
        <div>
          <p>
            {topic.article_count} correlated articles
          </p>
          <h3>{topic.label}</h3>
        </div>

        <span
          className="trend-badge"
          data-trend={topic.trend}
        >
          <TrendIcon aria-hidden="true" />
          {trendLabels[topic.trend]}
        </span>
      </header>

      <div className="topic-statistics">
        <div>
          <span>Recent</span>
          <strong>
            {topic.recent_article_count}
          </strong>
        </div>
        <div>
          <span>Previous</span>
          <strong>
            {topic.previous_article_count}
          </strong>
        </div>
        <div>
          <span>Trend score</span>
          <strong>
            {score > 0 ? '+' : ''}
            {score}%
          </strong>
        </div>
      </div>

      <div
        className="topic-keywords"
        aria-label="Topic keywords"
      >
        {topic.keywords.map((keyword) => (
          <span key={keyword}>{keyword}</span>
        ))}
      </div>

      {evidence.length > 0 && (
        <div className="topic-evidence">
          <h4>Observed evidence</h4>
          <div>
            {evidence.map((value) => (
              <span key={value}>{value}</span>
            ))}
          </div>
        </div>
      )}

      <div className="representative-list">
        <h4>Representative intelligence</h4>
        {topic.representative_articles.map(
          (article) => (
            <a
              key={article.article_id}
              href={article.link}
              target="_blank"
              rel="noreferrer"
            >
              <div>
                <strong>{article.title}</strong>
                <span>
                  {article.source.replaceAll(
                    '_',
                    ' ',
                  )}
                  {' · '}
                  {dateFormatter.format(
                    new Date(article.published),
                  )}
                </span>
              </div>
              <ExternalLink aria-hidden="true" />
            </a>
          ),
        )}
      </div>
    </article>
  )
}

function TopicsPage() {
  const [data, setData] =
    useState<EmergingTopicsResponse | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    const controller = new AbortController()

    getEmergingTopics(
      {
        observationDays: 30,
        recentDays: 7,
        limit: 10,
      },
      controller.signal,
    )
      .then(setData)
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
      <section className="topics-page">
        <div className="page-state" role="alert">
          <strong>
            Unable to detect emerging topics.
          </strong>
          <p>
            Confirm that PostgreSQL and the topic
            detection service are available.
          </p>
        </div>
      </section>
    )
  }

  if (!data) {
    return (
      <section className="topics-page">
        <div className="page-state" role="status">
          Detecting emerging topics…
        </div>
      </section>
    )
  }

  return (
    <section className="topics-page">
      <header className="page-heading">
        <div>
          <p>Semantic trend analysis</p>
          <h2>Emerging Threat Topics</h2>
          <span>
            Comparing the latest {data.recent_days}
            {' days against a '}
            {data.observation_days}-day window
          </span>
        </div>
      </header>

      <div className="topic-summary">
        <article aria-label="Considered articles">
          <span>Considered articles</span>
          <strong>
            {numberFormatter.format(
              data.considered_article_count,
            )}
          </strong>
        </article>
        <article aria-label="Clustered articles">
          <span>Clustered articles</span>
          <strong>
            {numberFormatter.format(
              data.clustered_article_count,
            )}
          </strong>
        </article>
        <article aria-label="Noise articles">
          <span>Noise articles</span>
          <strong>
            {numberFormatter.format(
              data.noise_article_count,
            )}
          </strong>
        </article>
      </div>

      {data.topics.length === 0 ? (
        <div className="empty-topics">
          No recurring topics were detected in this
          observation window.
        </div>
      ) : (
        <div className="topics-list">
          {data.topics.map((topic) => (
            <TopicCard
              key={`${topic.label}-${topic.article_count}`}
              topic={topic}
            />
          ))}
        </div>
      )}
    </section>
  )
}

export default TopicsPage