import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  getMitreSupportingArticles,
  getMitreTechniqueDetails,
  searchMitreTechniques,
} from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('MITRE API client', () => {
  it('searches MITRE techniques with filters', async () => {
    const responseBody = {
      keyword: 'PowerShell',
      limit: 5,
      offset: 2,
      domain: 'enterprise-attack',
      include_inactive: false,
      returned_count: 1,
      results: [],
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      searchMitreTechniques({
        keyword: '  PowerShell  ',
        limit: 5,
        offset: 2,
        domain: 'enterprise-attack',
      }),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/mitre/techniques'
        + '?keyword=PowerShell'
        + '&limit=5'
        + '&offset=2'
        + '&include_inactive=false'
        + '&domain=enterprise-attack'
      ),
      expect.any(Object),
    )
  })

  it('loads normalized MITRE technique details', async () => {
    const responseBody = {
      technique_id: 'T1566.002',
      name: 'Spearphishing Link',
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      getMitreTechniqueDetails(
        '  t1566.002  ',
      ),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/mitre/techniques/'
        + 'T1566.002'
      ),
      expect.any(Object),
    )
  })

  it('loads MITRE supporting articles', async () => {
    const responseBody = {
      technique_id: 'T1530',
      limit: 5,
      supporting_article_count: 1,
      returned_count: 1,
      articles: [],
    }

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      getMitreSupportingArticles(
        't1530',
        5,
      ),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/mitre/techniques/'
        + 'T1530/articles?limit=5'
      ),
      expect.any(Object),
    )
  })

  it('rejects an invalid technique before fetch', () => {
    const fetchMock = vi.fn()
  
    vi.stubGlobal('fetch', fetchMock)
  
    expect(() => {
      getMitreTechniqueDetails('T123')
    }).toThrow(
      'MITRE technique ID must follow '
      + 'the format TNNNN or TNNNN.NNN.',
    )
  
    expect(fetchMock).not.toHaveBeenCalled()
  })
})