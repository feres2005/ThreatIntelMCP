import {
  render,
  screen,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  MemoryRouter,
} from 'react-router-dom'
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

const {
  mockedSearchCves,
  mockedGetCveDetails,
  mockedGetCveSupportingArticles,
} = vi.hoisted(() => ({
  mockedSearchCves: vi.fn(),
  mockedGetCveDetails: vi.fn(),
  mockedGetCveSupportingArticles: vi.fn(),
}))

vi.mock('../../api/client', () => ({
  searchCves: mockedSearchCves,
  getCveDetails: mockedGetCveDetails,
  getCveSupportingArticles:
    mockedGetCveSupportingArticles,
}))

import {
  CveIntelligencePanel,
} from './CveIntelligencePanel'

const cveDetail = {
  cve_id: 'CVE-2026-50522',
  description: 'Critical remote vulnerability.',
  cvss_score: 9.8,
  severity: 'CRITICAL',
  published: '2026-06-01T12:00:00Z',
  last_modified: '2026-08-01T12:00:00Z',
  reference_links: [
    'https://example.com/cve-reference',
  ],
  enriched_at: '2026-08-23T03:00:00Z',
}

const supportingArticles = {
  cve_id: 'CVE-2026-50522',
  limit: 20,
  supporting_article_count: 1,
  returned_count: 1,
  articles: [
    {
      article_id: 13310,
      title: 'Critical vulnerability exploited',
      link: 'https://example.com/article-13310',
      source: 'the_hacker_news',
      published: '2026-08-20T12:00:00Z',
      severity: 'Critical',
      confidence_score: 0.92,
    },
  ],
}

beforeEach(() => {
  vi.resetAllMocks()
})

describe('CveIntelligencePanel', () => {
  it('searches cached CVEs and opens a result', async () => {
    const user = userEvent.setup()

    mockedSearchCves.mockResolvedValueOnce({
      keyword: 'critical',
      limit: 10,
      offset: 0,
      returned_count: 1,
      results: [
        {
          cve_id: 'CVE-2026-50522',
          description:
            'Critical remote vulnerability.',
          cvss_score: 9.8,
          severity: 'CRITICAL',
          published:
            '2026-06-01T12:00:00Z',
          last_modified:
            '2026-08-01T12:00:00Z',
        },
      ],
    })

    mockedGetCveDetails.mockResolvedValueOnce(
      cveDetail,
    )

    mockedGetCveSupportingArticles
      .mockResolvedValueOnce(
        supportingArticles,
      )

    render(
      <MemoryRouter>
        <CveIntelligencePanel />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /cve identifier, description or severity/i,
      }),
      'critical',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search cve intelligence/i,
      }),
    )

    expect(
      await screen.findByRole('button', {
        name: 'View CVE-2026-50522',
      }),
    ).toBeInTheDocument()

    expect(
      mockedSearchCves,
    ).toHaveBeenCalledWith(
      {
        keyword: 'critical',
        limit: 10,
        offset: 0,
      },
      expect.any(AbortSignal),
    )

    await user.click(
      screen.getByRole('button', {
        name: 'View CVE-2026-50522',
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'CVE-2026-50522',
      }),
    ).toBeInTheDocument()

    const descriptionPanel =
        screen.getByRole('region', {
            name: 'Vulnerability description',
        })

    expect(
        within(descriptionPanel).getByText(
            'Critical remote vulnerability.',
        ),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('heading', {
        name: 'Critical vulnerability exploited',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: /open investigation/i,
      }),
    ).toHaveAttribute(
      'href',
      '/articles/13310',
    )

    expect(
      screen.getByRole('link', {
        name: /open reference 1/i,
      }),
    ).toHaveAttribute(
      'href',
      'https://example.com/cve-reference',
    )
  })

  it('performs exact CVE lookup without cached search', async () => {
    const user = userEvent.setup()

    mockedGetCveDetails.mockResolvedValueOnce(
      cveDetail,
    )

    mockedGetCveSupportingArticles
      .mockResolvedValueOnce({
        ...supportingArticles,
        supporting_article_count: 0,
        returned_count: 0,
        articles: [],
      })

    render(
      <MemoryRouter>
        <CveIntelligencePanel />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /cve identifier, description or severity/i,
      }),
      'cve-2026-50522',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search cve intelligence/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'CVE-2026-50522',
      }),
    ).toBeInTheDocument()

    expect(
      mockedSearchCves,
    ).not.toHaveBeenCalled()

    expect(
      mockedGetCveDetails,
    ).toHaveBeenCalledWith(
      'CVE-2026-50522',
      expect.any(AbortSignal),
    )

    expect(
      mockedGetCveSupportingArticles,
    ).toHaveBeenCalledWith(
      'CVE-2026-50522',
      20,
      expect.any(AbortSignal),
    )

    expect(
      screen.getByText(
        /no stored article currently references/i,
      ),
    ).toBeInTheDocument()
  })
})