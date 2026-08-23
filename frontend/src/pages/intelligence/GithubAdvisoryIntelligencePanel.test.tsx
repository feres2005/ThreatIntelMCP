import {
  render,
  screen,
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

const {
  mockedSearch,
  mockedDetails,
  mockedArticles,
} = vi.hoisted(() => ({
  mockedSearch: vi.fn(),
  mockedDetails: vi.fn(),
  mockedArticles: vi.fn(),
}))

vi.mock('../../api/client', () => ({
  searchGithubAdvisories: mockedSearch,
  getGithubAdvisoryDetails: mockedDetails,
  getGithubAdvisorySupportingArticles:
    mockedArticles,
}))

import {
  GithubAdvisoryIntelligencePanel,
} from './GithubAdvisoryIntelligencePanel'

const advisoryDetails = {
  ghsa_id: 'GHSA-v667-gc2r-2xm7',
  cve_id: 'CVE-2026-55445',
  summary: 'Improper authentication.',
  severity: 'critical',
  ecosystem: 'npm',
  published_at: '2026-08-20T18:36:59',
  updated_at: '2026-08-20T18:37:00',
  cvss_v3_score: null,
  cvss_v4_score: 9.3,
  type: 'reviewed',
  description: 'Authentication can be bypassed.',
  github_reviewed_at: '2026-08-20T18:37:00',
  nvd_published_at: null,
  withdrawn_at: null,
  cvss_v3_vector: null,
  cvss_v4_vector: 'CVSS:4.0/test',
  cwe_ids: ['CWE-287'],
  reference_links: [
    'https://example.com/advisory',
  ],
  vulnerabilities: [
    {
      ecosystem: 'npm',
      package_name: 'example-package',
      vulnerable_version_range: '< 2.0.0',
      first_patched_version: '2.0.0',
      vulnerable_functions: null,
    },
  ],
}

const articleEvidence = {
  ghsa_id: 'GHSA-v667-gc2r-2xm7',
  cve_id: 'CVE-2026-55445',
  limit: 20,
  supporting_article_count: 1,
  returned_count: 1,
  articles: [
    {
      article_id: 13310,
      title: 'Authentication flaw exploited',
      link: 'https://example.com/article',
      source: 'the_hacker_news',
      published: null,
      severity: 'Critical',
      confidence_score: 0.92,
    },
  ],
}

beforeEach(() => {
  vi.clearAllMocks()

  mockedDetails.mockResolvedValue(
    advisoryDetails,
  )
  mockedArticles.mockResolvedValue(
    articleEvidence,
  )
})

describe(
  'GithubAdvisoryIntelligencePanel',
  () => {
    it('searches with advisory filters and opens details', async () => {
      const user = userEvent.setup()

      mockedSearch.mockResolvedValue({
        keyword: 'authentication',
        limit: 10,
        offset: 0,
        severity: 'critical',
        ecosystem: 'npm',
        returned_count: 1,
        results: [advisoryDetails],
      })

      render(
        <MemoryRouter>
          <GithubAdvisoryIntelligencePanel />
        </MemoryRouter>,
      )

      await user.type(
        screen.getByRole('searchbox', {
          name: /advisory identifier or keyword/i,
        }),
        'authentication',
      )

      await user.selectOptions(
        screen.getByRole('combobox', {
          name: /severity/i,
        }),
        'critical',
      )

      await user.selectOptions(
        screen.getByRole('combobox', {
          name: /package ecosystem/i,
        }),
        'npm',
      )

      await user.click(
        screen.getByRole('button', {
          name: /search github advisories/i,
        }),
      )

      expect(mockedSearch).toHaveBeenCalledWith({
        keyword: 'authentication',
        limit: 10,
        severity: 'critical',
        ecosystem: 'npm',
      })

      expect(
        await screen.findByRole('heading', {
          name: 'Improper authentication.',
        }),
      ).toBeInTheDocument()

      await user.click(
        screen.getByRole('button', {
          name: /view ghsa-v667-gc2r-2xm7/i,
        }),
      )

      expect(
        await screen.findByText(
          'Authentication can be bypassed.',
        ),
      ).toBeInTheDocument()

      expect(
        screen.getByText('example-package'),
      ).toBeInTheDocument()

      expect(
        screen.getByRole('link', {
          name: /open investigation/i,
        }),
      ).toHaveAttribute(
        'href',
        '/articles/13310',
      )
    })

    it('performs an exact GHSA lookup directly', async () => {
      const user = userEvent.setup()

      render(
        <MemoryRouter>
          <GithubAdvisoryIntelligencePanel />
        </MemoryRouter>,
      )

      await user.type(
        screen.getByRole('searchbox', {
          name: /advisory identifier or keyword/i,
        }),
        'GHSA-V667-GC2R-2XM7',
      )

      await user.click(
        screen.getByRole('button', {
          name: /search github advisories/i,
        }),
      )

      expect(mockedSearch).not.toHaveBeenCalled()
      expect(mockedDetails).toHaveBeenCalledWith(
        'GHSA-V667-GC2R-2XM7',
      )
      expect(mockedArticles).toHaveBeenCalledWith(
        'GHSA-V667-GC2R-2XM7',
      )

      expect(
        await screen.findByText(
          'Authentication can be bypassed.',
        ),
      ).toBeInTheDocument()
    })
  },
)