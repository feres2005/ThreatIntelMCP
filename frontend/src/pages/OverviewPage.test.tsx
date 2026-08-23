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

import {
  getHealth,
  getPipelineStatus,
} from '../api/client'
import OverviewPage from './OverviewPage'

vi.mock('../api/client', () => ({
  getHealth: vi.fn(),
  getPipelineStatus: vi.fn(),
}))

const mockedGetHealth = vi.mocked(getHealth)
const mockedGetPipelineStatus = vi.mocked(
  getPipelineStatus,
)

beforeEach(() => {
  mockedGetHealth.mockReset()
  mockedGetPipelineStatus.mockReset()

  mockedGetHealth.mockResolvedValue({
    status: 'healthy',
    service: 'ThreatIntelMCP REST API',
    version: '1.0.0',
  })

  mockedGetPipelineStatus.mockResolvedValue({
    operation: 'get_pipeline_status',
    health_status: 'attention_required',
    work_pending: {
      article_processing: 339,
      embedding_indexing: 0,
    },
    coverage: {
      processing_percent: 46.95,
      analysis_percent: 43.97,
      embedding_percent: 100,
    },
    counts: {
      total_articles: 639,
      processed_articles: 300,
      pending_articles: 339,
      analyzed_articles: 281,
      processed_without_analysis: 19,
      pending_with_analysis: 0,
      typed_ioc_rows: 0,
      articles_with_typed_iocs: 0,
      article_embeddings: 639,
      articles_missing_embeddings: 0,
      enriched_cves: 15,
      cached_otx_indicators: 17,
      mitre_techniques: 1140,
      github_advisories: 34640,
    },
    warnings: [
      '19 processed articles have no AI analysis.',
    ],
  })
})

describe('OverviewPage', () => {
  it('renders live operational intelligence', async () => {
    render(<OverviewPage />)

    expect(
      screen.getByText(/loading operational data/i),
    ).toBeInTheDocument()

    expect(
      await screen.findByRole('heading', {
        name: /operational overview/i,
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByText(/api healthy/i),
    ).toBeInTheDocument()

    expect(
      screen.getByLabelText('Total articles'),
    ).toHaveTextContent('639')

    expect(
      screen.getByLabelText('Analyzed articles'),
    ).toHaveTextContent('281')

    expect(
      screen.getByLabelText('GitHub advisories'),
    ).toHaveTextContent('34,640')

    expect(
      screen.getByRole('progressbar', {
        name: 'Processing coverage',
      }),
    ).toHaveAttribute('aria-valuenow', '46.95')

    expect(
      screen.getByText(
        '19 processed articles have no AI analysis.',
      ),
    ).toBeInTheDocument()
  })

  it('renders a controlled backend error', async () => {
    mockedGetHealth.mockRejectedValueOnce(
      new Error('Backend unavailable'),
    )

    render(<OverviewPage />)

    await waitFor(() => {
      expect(
        screen.getByRole('alert'),
      ).toHaveTextContent(
        'Unable to load operational data.',
      )
    })
  })
})