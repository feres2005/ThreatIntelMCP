import {
  type FormEvent,
  useEffect,
  useRef,
  useState,
} from 'react'
import { Link } from 'react-router-dom'
import './SemanticSearchPage.css'
import {
  semanticSearchArticles,
} from '../api/client'
import type {
  SemanticArticleSearchResponse,
} from '../api/types'

function formatSource(source: string): string {
  return source
    .split('_')
    .filter(Boolean)
    .map(
      (part) => (
        part.charAt(0).toUpperCase()
        + part.slice(1)
      ),
    )
    .join(' ')
}

function formatPublicationDate(
  published: string | null,
): string {
  if (!published) {
    return 'Publication date unavailable'
  }

  const date = new Date(published)

  if (Number.isNaN(date.getTime())) {
    return 'Publication date unavailable'
  }

  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function formatSimilarity(
  similarity: number,
): string {
  if (!Number.isFinite(similarity)) {
    return '0.0% similarity'
  }

  const percentage = Math.max(
    0,
    Math.min(1, similarity),
  ) * 100

  return `${percentage.toFixed(1)}% similarity`
}

export function SemanticSearchPage() {
  const [query, setQuery] = useState('')
  const [response, setResponse] =
    useState<SemanticArticleSearchResponse | null>(
      null,
    )
  const [error, setError] = useState<string | null>(
    null,
  )
  const [isLoading, setIsLoading] = useState(false)

  const activeRequest = useRef<AbortController | null>(
    null,
  )

  useEffect(
    () => () => {
      activeRequest.current?.abort()
    },
    [],
  )

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const normalizedQuery = query.trim()

    if (!normalizedQuery) {
      setError('Enter a threat description to search.')
      setResponse(null)
      return
    }

    activeRequest.current?.abort()

    const controller = new AbortController()
    activeRequest.current = controller

    setIsLoading(true)
    setError(null)

    try {
      const result = await semanticSearchArticles(
        {
          searchQuery: normalizedQuery,
          limit: 10,
        },
        controller.signal,
      )

      setResponse(result)
    } catch (requestError) {
      if (
        requestError instanceof Error
        && requestError.name === 'AbortError'
      ) {
        return
      }

      setResponse(null)
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Semantic search failed.',
      )
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null
        setIsLoading(false)
      }
    }
  }

  return (
    <section className="semantic-search-page">
      <header className="semantic-search-header">
        <p className="eyebrow">
          Vector intelligence retrieval
        </p>
        <h1>Semantic Search</h1>
        <p>
          Find related threat intelligence by meaning,
          even when articles use different terminology.
        </p>
      </header>

      <form
        className="semantic-search-form"
        onSubmit={handleSubmit}
        aria-label="Semantic article search"
      >
        <label htmlFor="semantic-search-query">
          Semantic search query
        </label>

        <div className="semantic-search-controls">
          <input
            id="semantic-search-query"
            type="search"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value)
            }}
            placeholder={
              'Example: North Korean phishing campaign'
            }
          />

          <button
            type="submit"
            disabled={isLoading}
          >
            {isLoading
              ? 'Searching…'
              : 'Search semantically'}
          </button>
        </div>
      </form>

      {error && (
        <div
          className="semantic-search-error"
          role="alert"
        >
          {error}
        </div>
      )}

      {response && (
        <section
          className="semantic-search-results"
          aria-label="Semantic search results"
        >
          <header>
            <p className="eyebrow">Search results</p>
            <h2>
              {response.returned_count} similar{' '}
              {response.returned_count === 1
                ? 'article'
                : 'articles'}
            </h2>
          </header>

          {response.results.length === 0 ? (
            <p className="semantic-search-empty">
              No semantically similar articles were found.
            </p>
          ) : (
            <div className="semantic-result-grid">
              {response.results.map((article) => (
                <article
                  className="semantic-result-card"
                  key={article.article_id}
                >
                  <div className="semantic-result-meta">
                    <span>
                      {formatSource(article.source)}
                    </span>
                    <strong>
                      {formatSimilarity(
                        article.similarity,
                      )}
                    </strong>
                  </div>

                  <h3>{article.title}</h3>

                  <p className="semantic-result-date">
                    {formatPublicationDate(
                      article.published,
                    )}
                  </p>

                  <p className="semantic-result-summary">
                    {article.summary?.trim()
                      || 'No analysis summary is available.'}
                  </p>

                  <div className="semantic-result-actions">
                    {article.analysis_available ? (
                        <Link
                            to={`/articles/${article.article_id}`}
                        >
                            Open investigation
                        </Link>
                    ) : (
                        <span className="investigation-unavailable">
                            Investigation unavailable
                        </span>
                )}

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
      )}
    </section>
  )
}