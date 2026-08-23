import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import { getEmergingTopics } from './client'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Emerging-topics API client', () => {
  it('sends the configured topic window', async () => {
    const responseBody = {
      generated_at: '2026-08-22T16:53:53Z',
      observation_days: 30,
      recent_days: 7,
      limit: 3,
      considered_article_count: 240,
      clustered_article_count: 36,
      noise_article_count: 204,
      topics: [],
    }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => responseBody,
    })

    vi.stubGlobal('fetch', fetchMock)

    await expect(
      getEmergingTopics({
        observationDays: 30,
        recentDays: 7,
        limit: 3,
      }),
    ).resolves.toEqual(responseBody)

    expect(fetchMock).toHaveBeenCalledWith(
      (
        '/api/v1/topics/emerging'
        + '?observation_days=30'
        + '&recent_days=7'
        + '&limit=3'
      ),
      expect.any(Object),
    )
  })
})