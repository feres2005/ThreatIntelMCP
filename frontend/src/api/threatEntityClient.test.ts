import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  getThreatEntityEvidence,
  searchThreatEntities,
} from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Threat entity API client', () => {
  it('searches an entity category', async () => {
    const responseBody = {
      entity_type: 'malware',
      keyword: 'ransom',
      limit: 5,
      offset: 2,
      returned_count: 1,
      results: [
        {
          value: 'Qilin',
          supporting_article_count: 2,
          latest_seen: (
            '2026-08-20T12:30:00Z'
          ),
        },
      ],
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      searchThreatEntities({
        entityType: 'malware',
        keyword: '  ransom  ',
        limit: 5,
        offset: 2,
      }),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/entities'
        + '?entity_type=malware'
        + '&keyword=ransom'
        + '&limit=5'
        + '&offset=2'
      ),
      expect.any(Object),
    )
  })

  it('loads supporting entity evidence', async () => {
    const responseBody = {
      entity_type: 'apt_group',
      value: 'Example Group',
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
      getThreatEntityEvidence({
        entityType: 'apt_group',
        value: '  Example Group  ',
        limit: 12,
      }),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/entities/evidence'
        + '?entity_type=apt_group'
        + '&value=Example+Group'
        + '&limit=12'
      ),
      expect.any(Object),
    )
  })

  it('rejects an empty keyword before fetch', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    expect(() => {
      searchThreatEntities({
        entityType: 'malware',
        keyword: '   ',
      })
    }).toThrow(
      'Entity search keyword must contain '
      + 'between 1 and 200 characters.',
    )

    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects an invalid evidence limit', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    expect(() => {
      getThreatEntityEvidence({
        entityType: 'targeted_sector',
        value: 'Government',
        limit: 51,
      })
    }).toThrow(
      'Entity evidence limit must be between '
      + '1 and 50.',
    )

    expect(fetchMock).not.toHaveBeenCalled()
  })
})