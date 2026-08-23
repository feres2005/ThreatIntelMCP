import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import { searchArticles,} from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Article-search API client', () => {
  it('normalizes and sends the search parameters', async () => {
    const responseBody = {
      keyword: 'Microsoft',
      limit: 3,
      offset: 0,
      returned_count: 0,
      results: [],
    }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      searchArticles({
        keyword: '  Microsoft  ',
        limit: 3,
        offset: 0,
      }),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/articles'
        + '?keyword=Microsoft'
        + '&limit=3'
        + '&offset=0'
      ),
      expect.any(Object),
    )
  })

  it('rejects an empty search locally', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      searchArticles({
        keyword: '   ',
      }),
    ).rejects.toThrow(
      'Search keyword is required.',
    )

    expect(fetchMock).not.toHaveBeenCalled()
  })
})