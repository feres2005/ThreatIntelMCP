import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  getGithubAdvisoryDetails,
  getGithubAdvisorySupportingArticles,
  searchGithubAdvisories,
} from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('GitHub advisory API client', () => {
  it('searches with severity and ecosystem filters', async () => {
    const responseBody = {
      keyword: 'authentication',
      limit: 5,
      offset: 2,
      severity: 'medium',
      ecosystem: 'npm',
      returned_count: 0,
      results: [],
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      searchGithubAdvisories({
        keyword: '  authentication  ',
        limit: 5,
        offset: 2,
        severity: 'medium',
        ecosystem: 'npm',
      }),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/github/advisories'
        + '?keyword=authentication'
        + '&limit=5'
        + '&offset=2'
        + '&severity=medium'
        + '&ecosystem=npm'
      ),
      expect.any(Object),
    )
  })

  it('loads normalized advisory details', async () => {
    const responseBody = {
      ghsa_id: 'GHSA-v667-gc2r-2xm7',
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      getGithubAdvisoryDetails(
        '  GHSA-V667-GC2R-2XM7  ',
      ),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/github/advisories/'
        + 'GHSA-v667-gc2r-2xm7'
      ),
      expect.any(Object),
    )
  })

  it('loads supporting articles', async () => {
    const responseBody = {
      ghsa_id: 'GHSA-v667-gc2r-2xm7',
      cve_id: 'CVE-2026-55445',
      limit: 12,
      supporting_article_count: 0,
      returned_count: 0,
      articles: [],
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      getGithubAdvisorySupportingArticles(
        'GHSA-V667-GC2R-2XM7',
        12,
      ),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/github/advisories/'
        + 'GHSA-v667-gc2r-2xm7'
        + '/articles?limit=12'
      ),
      expect.any(Object),
    )
  })

  it('rejects an invalid advisory ID before fetch', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    expect(() => {
      getGithubAdvisoryDetails('invalid-ghsa')
    }).toThrow(
      'GitHub advisory ID must follow the '
      + 'format GHSA-XXXX-XXXX-XXXX.',
    )

    expect(fetchMock).not.toHaveBeenCalled()
  })
})
