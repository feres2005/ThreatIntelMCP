import {
  render,
  screen,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  MemoryRouter,
} from 'react-router-dom'
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

const {
  mockedSearchMitreTechniques,
  mockedGetMitreTechniqueDetails,
  mockedGetMitreSupportingArticles,
} = vi.hoisted(() => ({
  mockedSearchMitreTechniques: vi.fn(),
  mockedGetMitreTechniqueDetails: vi.fn(),
  mockedGetMitreSupportingArticles: vi.fn(),
}))

vi.mock('../../api/client', () => ({
  searchMitreTechniques:
    mockedSearchMitreTechniques,
  getMitreTechniqueDetails:
    mockedGetMitreTechniqueDetails,
  getMitreSupportingArticles:
    mockedGetMitreSupportingArticles,
}))

import {
  MitreIntelligencePanel,
} from './MitreIntelligencePanel'

const techniqueDetail = {
  technique_id: 'T1566.002',
  stix_id: 'attack-pattern--example',
  name: 'Spearphishing Link',
  description:
    'Adversaries may send malicious links.',
  domain: 'enterprise-attack',
  is_subtechnique: true,
  platforms: [
    'Windows',
    'Linux',
    'macOS',
  ],
  kill_chain_phases: [
    {
      kill_chain_name: 'mitre-attack',
      phase_name: 'initial-access',
    },
  ],
  version: '1.4',
  reference_links: [
    {
      source_name: 'MITRE ATT&CK',
      url: 'https://example.com/T1566-002',
      external_id: 'T1566.002',
      description: null,
    },
  ],
  created: '2020-03-02T00:00:00Z',
  modified: '2026-04-15T00:00:00Z',
  revoked: false,
  deprecated: false,
}

const supportingEvidence = {
  technique_id: 'T1566.002',
  limit: 20,
  supporting_article_count: 1,
  returned_count: 1,
  articles: [
    {
      article_id: 12751,
      title: 'Phishing campaign investigation',
      link: 'https://example.com/article-12751',
      source: 'the_hacker_news',
      published: '2026-07-24T12:00:00Z',
      severity: 'High',
      confidence_score: 0.85,
    },
  ],
}

beforeEach(() => {
  vi.resetAllMocks()
})

describe('MitreIntelligencePanel', () => {
  it('searches techniques and opens details', async () => {
    const user = userEvent.setup()

    mockedSearchMitreTechniques
      .mockResolvedValueOnce({
        keyword: 'phishing',
        limit: 10,
        offset: 0,
        domain: 'enterprise-attack',
        include_inactive: true,
        returned_count: 1,
        results: [
          {
            technique_id: 'T1566.002',
            name: 'Spearphishing Link',
            domain: 'enterprise-attack',
            is_subtechnique: true,
            version: '1.4',
            revoked: false,
            deprecated: false,
          },
        ],
      })

    mockedGetMitreTechniqueDetails
      .mockResolvedValueOnce(
        techniqueDetail,
      )

    mockedGetMitreSupportingArticles
      .mockResolvedValueOnce(
        supportingEvidence,
      )

    render(
      <MemoryRouter>
        <MitreIntelligencePanel />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /technique identifier or keyword/i,
      }),
      'phishing',
    )

    await user.selectOptions(
        screen.getByRole('combobox', {
          name: 'ATT&CK domain',
        }),
      'enterprise-attack',
    )

    await user.click(
      screen.getByRole('checkbox', {
        name: /include revoked and deprecated/i,
      }),
    )

    await user.click(
        screen.getByRole('button', {
          name: 'Search ATT&CK',
        })
    )

    expect(
      await screen.findByRole('button', {
        name: 'View T1566.002',
      }),
    ).toBeInTheDocument()

    expect(
      mockedSearchMitreTechniques,
    ).toHaveBeenCalledWith(
      {
        keyword: 'phishing',
        limit: 10,
        offset: 0,
        domain: 'enterprise-attack',
        includeInactive: true,
      },
      expect.any(AbortSignal),
    )

    await user.click(
      screen.getByRole('button', {
        name: 'View T1566.002',
      }),
    )

    const detailPanel =
      await screen.findByRole('region', {
        name: 'MITRE technique details',
      })

    expect(
      within(detailPanel).getByRole(
        'heading',
        {
          name: 'Spearphishing Link',
        },
      ),
    ).toBeInTheDocument()

    expect(
      within(detailPanel).getByText(
        'Windows',
      ),
    ).toBeInTheDocument()

    expect(
      within(detailPanel).getByText(
        'initial-access',
      ),
    ).toBeInTheDocument()

    expect(
      within(detailPanel).getByRole(
        'heading',
        {
          name: 'Phishing campaign investigation',
        },
      ),
    ).toBeInTheDocument()
  })

  it('performs exact technique lookup directly', async () => {
    const user = userEvent.setup()

    mockedGetMitreTechniqueDetails
      .mockResolvedValueOnce(
        techniqueDetail,
      )

    mockedGetMitreSupportingArticles
      .mockResolvedValueOnce({
        ...supportingEvidence,
        supporting_article_count: 0,
        returned_count: 0,
        articles: [],
      })

    render(
      <MemoryRouter>
        <MitreIntelligencePanel />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /technique identifier or keyword/i,
      }),
      't1566.002',
    )

    await user.click(
        screen.getByRole('button', {
          name: 'Search ATT&CK',
        })
    )

    expect(
      await screen.findByRole('region', {
        name: 'MITRE technique details',
      }),
    ).toBeInTheDocument()

    expect(
      mockedSearchMitreTechniques,
    ).not.toHaveBeenCalled()

    expect(
      mockedGetMitreTechniqueDetails,
    ).toHaveBeenCalledWith(
      'T1566.002',
      expect.any(AbortSignal),
    )

    expect(
      screen.getByText(
        /no stored article currently references/i,
      ),
    ).toBeInTheDocument()
  })
})