import {
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import { searchArticles } from '../api/client'
import ArticlesPage from './ArticlesPage'

vi.mock('../api/client', () => ({
  searchArticles: vi.fn(),
}))

const mockedSearchArticles = vi.mocked(
  searchArticles,
)

beforeEach(() => {
  mockedSearchArticles.mockReset()

  mockedSearchArticles.mockResolvedValue({
    keyword: 'Microsoft',
    limit: 20,
    offset: 0,
    returned_count: 1,
    results: [
      {
        article_id: 12751,
        title: (
          'BlueNoroff Zoom Phishing Kit '
          + 'Profiles Crypto Wallets'
        ),
        summary: (
          'North Korean threat actors use '
          + 'phishing infrastructure.'
        ),
        severity: 'High',
        confidence_score: 0.85,
        cves: [],
        malware: [],
        mitre_techniques: [
          'T1598.003',
          'T1566.002',
        ],
      },
    ],
  })
})

describe('ArticlesPage', () => {

  it('renders an article with missing severity safely', async () => {
    const user = userEvent.setup()

    mockedSearchArticles.mockResolvedValueOnce({
      keyword: 'OpenAI',
      limit: 20,
      offset: 0,
      returned_count: 1,
      results: [
        {
          article_id: 14001,
          title: 'OpenAI security report',
          summary: 'A controlled article.',
          severity: null,
          confidence_score: 0,
          cves: [],
          malware: [],
          mitre_techniques: [],
        },
      ],
    })

    render(
      <MemoryRouter>
        <ArticlesPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /article keyword/i,
      }),
      'OpenAI',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search intelligence/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'OpenAI security report',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByText('Unknown'),
    ).toBeInTheDocument()
    })  

  it('searches and renders threat articles', async () => {
    const user = userEvent.setup()

    render(
      <MemoryRouter>
        <ArticlesPage />
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('heading', {
        name: /threat articles/i,
      }),
    ).toBeInTheDocument()

    expect(
      mockedSearchArticles,
    ).not.toHaveBeenCalled()

    await user.type(
      screen.getByRole('searchbox', {
        name: /article keyword/i,
      }),
      'Microsoft',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search intelligence/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: /bluenoroff zoom phishing kit/i,
      }),
    ).toBeInTheDocument()

    expect(
      mockedSearchArticles,
    ).toHaveBeenCalledWith(
      {
        keyword: 'Microsoft',
        limit: 20,
        offset: 0,
      },
      expect.any(AbortSignal),
    )

    expect(
      screen.getByText('High'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('85% confidence'),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: /open investigation/i,
      }),
    ).toHaveAttribute(
      'href',
      '/articles/12751',
    )
  })

  it('renders a controlled search error', async () => {
    const user = userEvent.setup()

    mockedSearchArticles.mockRejectedValueOnce(
      new Error('Search unavailable'),
    )

    render(
      <MemoryRouter>
        <ArticlesPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /article keyword/i,
      }),
      'ransomware',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search intelligence/i,
      }),
    )

    await waitFor(() => {
      expect(
        screen.getByRole('alert'),
      ).toHaveTextContent(
        'Unable to search threat articles.',
      )
    })
  })
})