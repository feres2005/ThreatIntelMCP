import {
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import {
  MemoryRouter,
  Route,
  Routes,
} from 'react-router-dom'
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  getArticleInvestigation,
  getArticleScoring,
} from '../api/client'
import ArticleInvestigationPage from './ArticleInvestigationPage'

vi.mock('../api/client', () => ({
  getArticleInvestigation: vi.fn(),
  getArticleScoring: vi.fn(),
}))

const mockedInvestigation = vi.mocked(
  getArticleInvestigation,
)
const mockedScoring = vi.mocked(
  getArticleScoring,
)

beforeEach(() => {
  mockedInvestigation.mockReset()
  mockedScoring.mockReset()

  mockedInvestigation.mockResolvedValue({
    article: {
      article_id: 12751,
      title: 'BlueNoroff phishing campaign',
      link: 'https://example.com/article',
      published: '2026-07-24T17:12:35Z',
      summary: (
        'North Korean threat actors use '
        + 'phishing infrastructure.'
      ),
      classification: [
        'phishing',
        'malware',
        'APT',
      ],
      severity: 'High',
      confidence_score: 0.85,
      iocs: [],
      cves: [],
      malware: [],
      mitre_techniques: [
        'T1566.002',
      ],
      apt_groups: ['BlueNoroff'],
      targeted_sectors: [],
      affected_technologies: [
        'Zoom',
        'Microsoft Teams',
      ],
    },
    typed_iocs: [],
    ioc_enrichment: [],
    cve_enrichment: [],
    mitre_enrichment: [
      {
        technique_id: 'T1566.002',
        enrichment_available: true,
        details: {
          name: 'Spearphishing Link',
          domain: 'enterprise-attack',
          is_subtechnique: true,
          platforms: [
            'Windows',
            'SaaS',
          ],
          kill_chain_phases: [
            {
              phase_name: 'initial-access',
              kill_chain_name: 'mitre-attack',
            },
          ],
          version: '2.8',
          revoked: false,
          deprecated: false,
        },
      },
    ],
  })

  mockedScoring.mockResolvedValue({
    target: {
      entity_type: 'article',
      article_id: 12751,
      title: 'BlueNoroff phishing campaign',
    },
    otx_selection: null,
    scoring_version: '1.0',
    threat: {
      scoring_version: '1.0',
      threat_score: 33,
      threat_level: 'Medium',
      evidence_present: true,
      components: {
        article_severity: {
          points: 22,
          maximum_points: 30,
        },
      },
      warnings: [],
    },
    confidence: {
      scoring_version: '1.0',
      confidence_score: 41.25,
      confidence_level: 'Medium',
      components: {
        ai_confidence: {
          points: 21.25,
          maximum_points: 25,
        },
      },
      warnings: [],
    },
    priority: {
      threat_level: 'Medium',
      confidence_level: 'Medium',
      priority_code: 'P3',
      priority_label: 'Moderate',
      recommended_action: 'Collect more evidence',
    },
    warnings: [],
  })
})

function renderPage() {
  render(
    <MemoryRouter
      initialEntries={['/articles/12751']}
    >
      <Routes>
        <Route
          path="/articles/:articleId"
          element={<ArticleInvestigationPage />}
        />
      </Routes>
    </MemoryRouter>,
  )
}

describe('ArticleInvestigationPage', () => {
  it('renders investigation and scoring evidence', async () => {
    renderPage()

    expect(
      screen.getByText(/building investigation/i),
    ).toBeInTheDocument()

    expect(
      await screen.findByRole('heading', {
        name: /bluenoroff phishing campaign/i,
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByLabelText('Threat score'),
    ).toHaveTextContent('33')

    expect(
      screen.getByLabelText('Confidence score'),
    ).toHaveTextContent('41.25')

    expect(
      screen.getByText('P3'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('Collect more evidence'),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('heading', {
        name: /spearphishing link/i,
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: /open source article/i,
      }),
    ).toHaveAttribute(
      'href',
      'https://example.com/article',
    )
  })

  it('renders a controlled investigation error', async () => {
    mockedInvestigation.mockRejectedValueOnce(
      new Error('Investigation unavailable'),
    )

    renderPage()

    await waitFor(() => {
      expect(
        screen.getByRole('alert'),
      ).toHaveTextContent(
        'Unable to build this investigation.',
      )
    })
  })
})