import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  getArticleDetails,
  getArticleInvestigation,
  getArticleScoring,
} from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Article-investigation API client', () => {
  it.each([
    [
      getArticleDetails,
      '/api/v1/articles/12751',
    ],
    [
      getArticleInvestigation,
      '/api/v1/articles/12751/investigation',
    ],
    [
      getArticleScoring,
      '/api/v1/articles/12751/score',
    ],
  ])(
    'requests the expected article endpoint',
    async (requestFunction, expectedPath) => {
      const responseBody = {
        article_id: 12751,
      }
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => responseBody,
      })

      vi.stubGlobal('fetch', fetchMock)

      await expect(
        requestFunction(12751),
      ).resolves.toEqual(responseBody)

      expect(fetchMock).toHaveBeenCalledWith(
        expectedPath,
        expect.any(Object),
      )
    },
  )

  it.each([0, -1, 1.5, Number.NaN])(
    'rejects invalid article ID %s',
    (articleId) => {
      expect(() => {
        getArticleDetails(articleId)
      }).toThrow(
        'Article ID must be a positive integer.',
      )
    },
  )
})