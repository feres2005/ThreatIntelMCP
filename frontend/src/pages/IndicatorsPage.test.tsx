import {
  render,
  screen,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import {
  describe,
  expect,
  it,
  vi,
} from 'vitest'

const {
  mockedGetIndicatorCorrelation,
  mockedGetIndicatorScoring,
} = vi.hoisted(() => ({
  mockedGetIndicatorCorrelation: vi.fn(),
  mockedGetIndicatorScoring: vi.fn(),
}))

vi.mock('../api/client', () => ({
  getIndicatorCorrelation:
    mockedGetIndicatorCorrelation,
  getIndicatorScoring:
    mockedGetIndicatorScoring,
}))

import { IndicatorsPage } from './IndicatorsPage'

describe('IndicatorsPage', () => {
  it('renders local sightings and related intelligence without OTX', async () => {
    const user = userEvent.setup()

    mockedGetIndicatorCorrelation.mockResolvedValueOnce({
      indicator: 'malicious.example',
      indicator_type: 'domain',
      supporting_article_count: 1,
      supporting_article_ids: [4838],
      supporting_articles: [
        {
          article_id: 4838,
          title: 'Supply chain attack investigation',
          link: 'https://example.com/article-4838',
          published: '2026-07-10T12:00:00Z',
          severity: 'High',
          confidence_score: 0.85,
        },
      ],
      related_entities: {
        cves: [
          {
            value: 'CVE-2026-48558',
            supporting_article_count: 1,
            supporting_article_ids: [4838],
          },
        ],
        malware: [
          {
            value: 'ExampleStealer',
            supporting_article_count: 1,
            supporting_article_ids: [4838],
          },
        ],
        mitre_techniques: [
          {
            value: 'T1566.002',
            supporting_article_count: 1,
            supporting_article_ids: [4838],
          },
        ],
        apt_groups: [],
        targeted_sectors: [],
        affected_technologies: [],
      },
      otx_enrichment: null,
    })

    mockedGetIndicatorScoring.mockResolvedValueOnce({
      target: {
        entity_type: 'indicator',
        indicator: 'malicious.example',
        indicator_type: 'domain',
      },
      scoring_version: '1.0',
      threat: {
        threat_score: 72,
        threat_level: 'High',
      },
      confidence: {
        confidence_score: 80,
        confidence_level: 'High',
      },
      priority: {
        priority_code: 'P2',
        priority_label: 'High',
        recommended_action:
          'Prioritize investigation',
      },
      warnings: [],
    })

    render(
      <MemoryRouter>
        <IndicatorsPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /indicator value/i,
      }),
      'malicious.example',
    )

    await user.click(
      screen.getByRole('button', {
        name: /investigate indicator/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'malicious.example',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('heading', {
        name: 'Supply chain attack investigation',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: /open investigation/i,
      }),
    ).toHaveAttribute(
      'href',
      '/articles/4838',
    )

    expect(
      screen.getByText('CVE-2026-48558'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('ExampleStealer'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('T1566.002'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('OTX intelligence not requested'),
    ).toBeInTheDocument()

    expect(
      mockedGetIndicatorCorrelation,
    ).toHaveBeenCalledWith({
      indicator: 'malicious.example',
      includeOtx: false,
    })
  })  
  it('renders OTX intelligence without local sightings', async () => {
    const user = userEvent.setup()

    mockedGetIndicatorCorrelation.mockResolvedValueOnce({
      indicator: '44d88612fea8a8f36de82e1278abb02f',
      indicator_type: 'FileHash-MD5',
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
      otx_enrichment: {
        indicator:
          '44d88612fea8a8f36de82e1278abb02f',
        indicator_type: 'FileHash-MD5',
        reputation: null,
        pulse_count: 50,
        country: 'Switzerland',
        country_code: 'CH',
        asn: 'AS8556 levantis hosting gmbh',
        malware_families: [],
        adversaries: [],
        industries: [],
        validation: [
          {
            name: 'Whitelisted hash',
            source: 'whitelist',
            message: 'Whitelisted hash: MISP',
          },
        ],
        sections: ['general', 'analysis'],
        last_checked: '2026-08-23T01:54:33.532286',
      },
    })

    mockedGetIndicatorScoring.mockResolvedValueOnce({
      target: {
        entity_type: 'indicator',
        indicator:
          '44d88612fea8a8f36de82e1278abb02f',
        indicator_type: 'FileHash-MD5',
      },
      scoring_version: '1.0',
      threat: {
        threat_score: 0,
        threat_level: 'Informational',
      },
      confidence: {
        confidence_score: 20,
        confidence_level: 'Low',
      },
      priority: {
        priority_code: 'P5',
        priority_label: 'Informational',
        recommended_action: 'No immediate action',
      },
      warnings: [
        {
          source: 'threat',
          message: (
            'OTX whitelist or false-positive evidence '
            + 'removed the OTX threat contribution.'
          ),
        },
      ],
    })

    render(
      <MemoryRouter>
        <IndicatorsPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /indicator value/i,
      }),
      '44d88612fea8a8f36de82e1278abb02f',
    )

    await user.click(
      screen.getByRole('checkbox', {
        name: /include OTX intelligence/i,
      }),
    )

    await user.click(
      screen.getByRole('button', {
        name: /investigate indicator/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: '44d88612fea8a8f36de82e1278abb02f',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByText('FileHash-MD5'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('50 OTX pulses'),
    ).toBeInTheDocument()
    
    expect(
      screen.getByText('Switzerland (CH)'),
    ).toBeInTheDocument()

    expect(
      screen.getByText(
        'AS8556 levantis hosting gmbh',
      ),
    ).toBeInTheDocument()

    expect(
      screen.getByText('No local article sightings'),
    ).toBeInTheDocument()

    expect(
      screen.getByText('P5'),
    ).toBeInTheDocument()

    expect(
      screen.getByText(
        /whitelist or false-positive evidence/i,
      ),
    ).toBeInTheDocument()

    expect(
      mockedGetIndicatorCorrelation,
    ).toHaveBeenCalledWith(
      {
        indicator:
          '44d88612fea8a8f36de82e1278abb02f',
        includeOtx: true,
      },
    )

    expect(
      mockedGetIndicatorScoring,
    ).toHaveBeenCalledWith(
      {
        indicator:
          '44d88612fea8a8f36de82e1278abb02f',
        includeOtx: true,
      },
    )
  })
})
