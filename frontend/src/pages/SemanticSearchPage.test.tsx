import {
  render,
  screen,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import {
  describe,
  expect,
  it,
  vi,
} from 'vitest'

const { mockedSemanticSearchArticles } = vi.hoisted(
  () => ({
    mockedSemanticSearchArticles: vi.fn(),
  }),
)

vi.mock('../api/client', () => ({
  semanticSearchArticles:
    mockedSemanticSearchArticles,
}))

import { SemanticSearchPage } from './SemanticSearchPage'

describe('SemanticSearchPage', () => {
    it('does not offer investigation without analysis', async () => {
      const user = userEvent.setup()

      mockedSemanticSearchArticles.mockResolvedValueOnce({
        search_query: 'AI compute hijacking',
        limit: 10,
        returned_count: 1,
        results: [
          {
            article_id: 2563,
            title: 'ThreatsDay AI Compute Hijacking',
            link: 'https://example.com/article-2563',
            source: 'the_hacker_news',
            published: null,
            summary: 'A raw RSS summary.',
            analysis_available: false,
            similarity: 0.871,
          },
        ],
      })

      render(
        <MemoryRouter>
          <SemanticSearchPage />
        </MemoryRouter>,
      )

      await user.type(
        screen.getByRole('searchbox', {
          name: /semantic search query/i,
        }),
        'AI compute hijacking',
      )

      await user.click(
        screen.getByRole('button', {
          name: /search semantically/i,
        }),
      )

      expect(
        await screen.findByRole('heading', {
          name: 'ThreatsDay AI Compute Hijacking',
        }),
      ).toBeInTheDocument()

      expect(
        screen.queryByRole('link', {
          name: /open investigation/i,
        }),
      ).not.toBeInTheDocument()

      expect(
        screen.getByText('Investigation unavailable'),
      ).toBeInTheDocument()

      expect(
        screen.getByRole('link', {
          name: /open source/i,
        }),
      ).toBeInTheDocument()
        })  
  it('searches and renders semantically similar articles', async () => {
    const user = userEvent.setup()

    mockedSemanticSearchArticles.mockResolvedValueOnce({
      search_query: 'North Korean phishing campaign',
      limit: 10,
      returned_count: 1,
      results: [
        {
          article_id: 4834,
          title: 'North Korean campaign',
          link: 'https://example.com/article',
          source: 'the_hacker_news',
          published: null,
          summary: null,
          analysis_available: true,
          similarity: 0.875953,
          
        },
      ],
    })

    render(
      <MemoryRouter>
        <SemanticSearchPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /semantic search query/i,
      }),
      'North Korean phishing campaign',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search semantically/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'North Korean campaign',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByText('87.6% similarity'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('Publication date unavailable'),
    ).toBeInTheDocument()
  })
})