import {
  Search,
  ShieldAlert,
} from 'lucide-react'
import {
  type FormEvent,
  useEffect,
  useRef,
  useState,
} from 'react'
import { Link } from 'react-router-dom'

import { searchArticles } from '../api/client'
import type {
  ArticleSearchResponse,
} from '../api/types'

import './ArticlesPage.css'

type SearchState =
  | 'idle'
  | 'loading'
  | 'success'
  | 'error'

function ArticlesPage() {
  const [keyword, setKeyword] = useState('')
  const [state, setState] =
    useState<SearchState>('idle')
  const [response, setResponse] =
    useState<ArticleSearchResponse | null>(null)

  const requestController =
    useRef<AbortController | null>(null)

  useEffect(() => {
    return () => {
      requestController.current?.abort()
    }
  }, [])

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const normalizedKeyword = keyword.trim()

    if (!normalizedKeyword) {
      return
    }

    requestController.current?.abort()

    const controller = new AbortController()
    requestController.current = controller

    setState('loading')

    try {
      const result = await searchArticles(
        {
          keyword: normalizedKeyword,
          limit: 20,
          offset: 0,
        },
        controller.signal,
      )

      if (!controller.signal.aborted) {
        setResponse(result)
        setState('success')
      }
    } catch {
      if (!controller.signal.aborted) {
        setResponse(null)
        setState('error')
      }
    }
  }

  return (
    <section className="articles-page">
      <header className="page-heading">
        <div>
          <p>Intelligence repository</p>
          <h2>Threat Articles</h2>
          <span>
            Search analyzed reporting and open a
            complete SOC investigation.
          </span>
        </div>
      </header>

      <form
        className="article-search"
        role="search"
        onSubmit={handleSubmit}
      >
        <label htmlFor="article-keyword">
          Article keyword
        </label>

        <div>
          <Search aria-hidden="true" />
          <input
            id="article-keyword"
            type="search"
            value={keyword}
            placeholder="Microsoft, ransomware, CVE…"
            onChange={(event) => {
              setKeyword(event.target.value)
            }}
          />
          <button
            type="submit"
            disabled={
              state === 'loading'
              || !keyword.trim()
            }
          >
            {state === 'loading'
              ? 'Searching…'
              : 'Search intelligence'}
          </button>
        </div>
      </form>

      {state === 'idle' && (
        <div className="article-empty-state">
          <ShieldAlert aria-hidden="true" />
          <strong>
            Start with a threat keyword
          </strong>
          <span>
            Search article titles, summaries and
            extracted intelligence.
          </span>
        </div>
      )}

      {state === 'error' && (
        <div className="page-state" role="alert">
          <strong>
            Unable to search threat articles.
          </strong>
          <p>
            Confirm that the backend and PostgreSQL
            are available.
          </p>
        </div>
      )}

      {state === 'success'
        && response
        && (
          <div className="article-results">
            <header>
              <div>
                <p>Search results</p>
                <h3>
                  {response.returned_count}
                  {' matches for “'}
                  {response.keyword}
                  {'”'}
                </h3>
              </div>
            </header>

            {response.results.length === 0 ? (
              <div className="article-empty-state">
                No analyzed articles matched this
                keyword.
              </div>
            ) : (
              <div className="article-list">
                {response.results.map((article) => (
                  <article
                    key={article.article_id}
                    className="article-card"
                  >
                    <header>
                      <span
                        className="severity-badge"
                        data-severity={
                          (article.severity?.trim() || 'Unknown').toLowerCase()
                      }
                      >
                        {article.severity?.trim() || 'Unknown'}
                      </span>
                      <span className="confidence">
                        {Math.round(
                          article.confidence_score
                          * 100,
                        )}
                        % confidence
                      </span>
                    </header>

                    <h3>{article.title}</h3>
                    <p>{article.summary}</p>

                    <div className="article-entities">
                      {article.cves.map((cve) => (
                        <span key={cve}>{cve}</span>
                      ))}
                      {article.malware.map((malware) => (
                        <span key={malware}>
                          {malware}
                        </span>
                      ))}
                      {article.mitre_techniques.map(
                        (technique) => (
                          <span key={technique}>
                            {technique}
                          </span>
                        ),
                      )}
                    </div>

                    <Link
                      to={`/articles/${article.article_id}`}
                    >
                      Open investigation
                    </Link>
                  </article>
                ))}
              </div>
            )}
          </div>
        )}
    </section>
  )
}

export default ArticlesPage