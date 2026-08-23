import {
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import { getEmergingTopics } from '../api/client'
import TopicsPage from './TopicsPage'

vi.mock('../api/client', () => ({
  getEmergingTopics: vi.fn(),
}))

const mockedGetEmergingTopics = vi.mocked(
  getEmergingTopics,
)

beforeEach(() => {
  mockedGetEmergingTopics.mockReset()

  mockedGetEmergingTopics.mockResolvedValue({
    generated_at: '2026-08-22T16:53:53Z',
    observation_days: 30,
    recent_days: 7,
    limit: 10,
    considered_article_count: 240,
    clustered_article_count: 36,
    noise_article_count: 204,
    topics: [
      {
        label: 'elementor / wordpress / flaw',
        keywords: [
          'elementor',
          'wordpress',
          'flaw',
        ],
        article_count: 3,
        recent_article_count: 3,
        previous_article_count: 0,
        recent_share: 0.0323,
        previous_share: 0,
        trend: 'rising',
        trend_score: 1,
        sources: [
          'bleeping_computer',
          'the_hacker_news',
        ],
        classifications: ['vulnerability'],
        severities: ['High'],
        cves: ['CVE-2026-90001'],
        malware: [],
        mitre_techniques: [],
        apt_groups: [],
        targeted_sectors: [],
        affected_technologies: ['WordPress'],
        representative_articles: [
          {
            article_id: 13301,
            title: 'Elementor Pro flaw enables RCE',
            link: 'https://example.com/elementor',
            source: 'the_hacker_news',
            published: '2026-08-20T08:04:34Z',
            similarity_to_centroid: 0.979,
          },
        ],
      },
    ],
  })
})

describe('TopicsPage', () => {
  it('renders detected topics and evidence', async () => {
    render(<TopicsPage />)

    expect(
      screen.getByText(/detecting emerging topics/i),
    ).toBeInTheDocument()

    expect(
      await screen.findByRole('heading', {
        name: /emerging threat topics/i,
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByLabelText('Clustered articles'),
    ).toHaveTextContent('36')

    expect(
      screen.getByRole('heading', {
        name: /elementor \/ wordpress \/ flaw/i,
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByText('Rising'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('CVE-2026-90001'),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: /elementor pro flaw enables rce/i,
      }),
    ).toHaveAttribute(
      'href',
      'https://example.com/elementor',
    )
  })

  it('renders a controlled detection error', async () => {
    mockedGetEmergingTopics.mockRejectedValueOnce(
      new Error('Topic detection unavailable'),
    )

    render(<TopicsPage />)

    await waitFor(() => {
      expect(
        screen.getByRole('alert'),
      ).toHaveTextContent(
        'Unable to detect emerging topics.',
      )
    })
  })
})