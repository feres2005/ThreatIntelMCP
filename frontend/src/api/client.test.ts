import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  ApiError,
  getHealth,
  getPipelineStatus,
  semanticSearchArticles,
  getIndicatorCorrelation,
  getIndicatorScoring,
  getCveDetails,
  getCveSupportingArticles,
  searchCves,
} from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('API client', () => {
    it('loads indicator scoring with the same OTX option', async () => {
      const responseBody = {
        target: {
          entity_type: 'indicator',
          indicator: 'example.com',
          indicator_type: 'domain',
        },
        scoring_version: '1.0',
        threat: {
          threat_score: 25,
          threat_level: 'Low',
        },
        confidence: {
          confidence_score: 40,
          confidence_level: 'Medium',
        },
        priority: {
          priority_code: 'P4',
          priority_label: 'Low',
          recommended_action: 'Collect more evidence',
        },
        warnings: [],
      }

      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => responseBody,
      })

      vi.stubGlobal('fetch', fetchMock)

      await expect(
        getIndicatorScoring({
          indicator: '  example.com  ',
          includeOtx: false,
        }),
      ).resolves.toEqual(responseBody)

      expect(fetchMock).toHaveBeenCalledWith(
        (
          '/api/v1/indicators/score'
          + '?indicator=example.com'
          + '&include_otx=false'
        ),
        expect.any(Object),
      )
    })
    it('searches cached CVE intelligence', async () => {
        const responseBody = {
          keyword: 'critical',
          limit: 5,
          offset: 2,
          returned_count: 1,
          results: [
            {
              cve_id: 'CVE-2026-50522',
              description: 'Critical vulnerability.',
              cvss_score: 9.8,
              severity: 'CRITICAL',
              published: '2026-06-01T12:00:00',
              last_modified: '2026-08-01T12:00:00',
            },
          ],
        }

        const fetchMock = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => responseBody,
        })

        vi.stubGlobal('fetch', fetchMock)

        await expect(
          searchCves({
            keyword: '  critical  ',
            limit: 5,
            offset: 2,
          }),
        ).resolves.toEqual(responseBody)

        expect(fetchMock).toHaveBeenCalledWith(
          (
            '/api/v1/cves?keyword=critical'
            + '&limit=5&offset=2'
          ),
          expect.any(Object),
        )
  })    

  it('loads exact CVE intelligence', async () => {
        const responseBody = {
          cve_id: 'CVE-2026-50522',
          description: 'Critical vulnerability.',
          cvss_score: 9.8,
          severity: 'CRITICAL',
          published: '2026-06-01T12:00:00',
          last_modified: '2026-08-01T12:00:00',
          reference_links: [
            'https://example.com/advisory',
          ],
          enriched_at: '2026-08-23T03:30:00',
        }

        const fetchMock = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => responseBody,
        })

        vi.stubGlobal('fetch', fetchMock)

        await expect(
          getCveDetails(
            '  cve-2026-50522  ',
          ),
        ).resolves.toEqual(responseBody)

        expect(fetchMock).toHaveBeenCalledWith(
          '/api/v1/cves/CVE-2026-50522',
          expect.any(Object),
        )
    })    

  it('loads CVE supporting articles', async () => {
        const responseBody = {
          cve_id: 'CVE-2026-50522',
          limit: 5,
          supporting_article_count: 1,
          returned_count: 1,
          articles: [
            {
              article_id: 501,
              title: 'Critical package vulnerability',
              link: 'https://example.com/article-501',
              source: 'example_feed',
              published: null,
              severity: 'Critical',
              confidence_score: 0.91,
            },
          ],
        }

        const fetchMock = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => responseBody,
        })

        vi.stubGlobal('fetch', fetchMock)

        await expect(
          getCveSupportingArticles(
            'cve-2026-50522',
            5,
          ),
        ).resolves.toEqual(responseBody)

        expect(fetchMock).toHaveBeenCalledWith(
          (
            '/api/v1/cves/CVE-2026-50522'
            + '/articles?limit=5'
          ),
          expect.any(Object),
        )
  })    

  it('rejects an invalid CVE identifier locally', () => {
        expect(
          () => getCveDetails('not-a-cve'),
        ).toThrow(
          'CVE ID must follow the format '
          + 'CVE-YYYY-NNNN.',
        )
  })
    })
    it('loads indicator correlation with optional OTX intelligence', async () => {
        const responseBody = {
          indicator: 'example.com',
          indicator_type: 'domain',
          supporting_article_count: 0,
          supporting_article_ids: [],
          supporting_articles: [],
          related_entities: {
            cves: [],
            malware: [],
            mitre_techniques: [],
            apt_groups: [],
            targeted_sectors: [],
            affected_technologies: [],
          },
          otx_enrichment: null,
        }

        const fetchMock = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => responseBody,
        })

        vi.stubGlobal('fetch', fetchMock)

        await expect(
          getIndicatorCorrelation({
            indicator: '  example.com  ',
            includeOtx: true,
          }),
        ).resolves.toEqual(responseBody)

        expect(fetchMock).toHaveBeenCalledWith(
          (
            '/api/v1/indicators/correlation'
            + '?indicator=example.com'
            + '&include_otx=true'
          ),
          expect.any(Object),
        )
    })    

  it('loads health through the relative API path', async () => {
    const responseBody = {
      status: 'healthy',
      service: 'ThreatIntelMCP REST API',
      version: '1.0.0',
    }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(getHealth()).resolves.toEqual(
      responseBody,
    )
    expect(fetchMock).toHaveBeenCalledWith(
      '/health',
      expect.objectContaining({
        headers: {
          Accept: 'application/json',
        },
      }),
    )
  })

  it('loads the pipeline status', async () => {
    const responseBody = {
      operation: 'get_pipeline_status',
      health_status: 'healthy',
      work_pending: {
        article_processing: 0,
        embedding_indexing: 0,
      },
      coverage: {
        processing_percent: 100,
        analysis_percent: 100,
        embedding_percent: 100,
      },
      counts: {},
      warnings: [],
    }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      getPipelineStatus(),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/pipeline/status',
      expect.any(Object),
    )
  })

  it('loads semantic article search results', async () => {
  const responseBody = {
    search_query: 'North Korean phishing campaign',
    limit: 5,
    returned_count: 1,
    results: [
      {
        article_id: 4834,
        title: 'North Korean campaign',
        link: 'https://example.com/article',
        source: 'the_hacker_news',
        published: null,
        summary: null,
        analysis_available: false,
        similarity: 0.8759,
      },
    ],
  }

  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => responseBody,
  })

  vi.stubGlobal('fetch', fetchMock)

  await expect(
    semanticSearchArticles({
      searchQuery: '  North Korean phishing campaign  ',
      limit: 5,
    }),
  ).resolves.toEqual(responseBody)

  expect(fetchMock).toHaveBeenCalledWith(
    (
      '/api/v1/search/articles/semantic'
      + '?search_query=North+Korean+phishing+campaign'
      + '&limit=5'
    ),
    expect.any(Object),
  )
})

  it('converts unsuccessful responses to ApiError', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({
        detail: 'Pipeline unavailable.',
      }),
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(getPipelineStatus()).rejects.toEqual(
      new ApiError(503, 'Pipeline unavailable.'),
    )
  })
