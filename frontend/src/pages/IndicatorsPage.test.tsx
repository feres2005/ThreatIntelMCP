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

const emptyRelatedEntities = {
  cves: [],
  malware: [],
  mitre_techniques: [],
  apt_groups: [],
  targeted_sectors: [],
  affected_technologies: [],
}

describe('IndicatorsPage', () => {
  it('prioritizes VirusTotal and OTX before local corroboration', async () => {
    const user = userEvent.setup()
    const hash = (
      '1e809b5361699f505e401acf98f79034'
      + 'fc89c4e95c9a99aabf88628da836ce3a'
    )

    mockedGetIndicatorCorrelation.mockResolvedValueOnce({
      indicator: hash,
      indicator_type: 'FileHash-SHA256',
      supporting_article_count: 1,
      supporting_article_ids: [4838],
      supporting_articles: [
        {
          article_id: 4838,
          title: 'Shell malware investigation',
          link: 'https://example.com/article-4838',
          published: '2026-08-20T12:00:00Z',
          severity: 'High',
          confidence_score: 0.91,
        },
      ],
      related_entities: {
        ...emptyRelatedEntities,
        malware: [
          {
            value: 'ExampleShell',
            supporting_article_count: 1,
            supporting_article_ids: [4838],
          },
        ],
      },
      otx_enrichment: {
        indicator: hash,
        indicator_type: 'FileHash-SHA256',
        reputation: 0,
        pulse_count: 5,
        country: null,
        country_code: null,
        asn: null,
        malware_families: [],
        adversaries: [],
        industries: [],
        validation: [],
        sections: ['general'],
        last_checked: '2026-08-24T08:30:00Z',
      },
      virustotal_enrichment: {
        indicator: hash,
        indicator_type: 'FileHash-SHA256',
        report_available: true,
        resource_type: 'file',
        resource_id: hash,
        malicious_count: 28,
        suspicious_count: 0,
        harmless_count: 0,
        undetected_count: 33,
        timeout_count: 0,
        failure_count: 0,
        type_unsupported_count: 0,
        confirmed_timeout_count: 0,
        total_engine_count: 61,
        total_result_count: 75,
        reputation: 0,
        community_votes: {
          harmless: 0,
          malicious: 4,
        },
        detections: [
          {
            engine_name: 'ExampleAV',
            category: 'malicious',
            result: 'Trojan.GenericKDZ',
            method: 'blacklist',
          },
        ],
        categories: [],
        tags: ['shell'],
        names: ['sample.sh'],
        meaningful_name: 'sample.sh',
        file_type: 'Shell script',
        country: null,
        asn: null,
        as_owner: null,
        last_analysis_date: '2026-08-24T08:29:49Z',
        permalink: 'https://www.virustotal.com/gui/file/example',
        last_checked: '2026-08-24T08:30:00Z',
        source: 'virustotal',
        cache_status: 'refreshed',
        is_stale: false,
      },
    })

    mockedGetIndicatorScoring.mockResolvedValueOnce({
      target: {
        entity_type: 'indicator',
        indicator: hash,
        indicator_type: 'FileHash-SHA256',
      },
      scoring_version: '2.0',
      threat: {
        threat_score: 45,
        threat_level: 'High',
      },
      confidence: {
        confidence_score: 35,
        confidence_level: 'Medium',
      },
      priority: {
        priority_code: 'P2',
        priority_label: 'High',
        recommended_action: 'Validate immediately',
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
      hash,
    )
    await user.click(
      screen.getByRole('button', {
        name: /investigate indicator/i,
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: hash,
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', {
        name: 'Primary intelligence sources',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', {
        name: 'VirusTotal',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', {
        name: 'AlienVault OTX',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByLabelText(
        'VirusTotal detection ratio',
      ),
    ).toHaveTextContent('28 / 61')
    expect(
      screen.getByText('Trojan.GenericKDZ'),
    ).toBeInTheDocument()
    expect(screen.getByText('P2')).toBeInTheDocument()
    expect(
      screen.getByRole('heading', {
        name: 'Shell malware investigation',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByText('ExampleShell'),
    ).toBeInTheDocument()

    const expectedRequest = {
      indicator: hash,
      includeOtx: true,
      includeVirusTotal: true,
    }

    expect(
      mockedGetIndicatorCorrelation,
    ).toHaveBeenCalledWith(expectedRequest)
    expect(
      mockedGetIndicatorScoring,
    ).toHaveBeenCalledWith(expectedRequest)
  })

  it('shows external no-report states without requiring local evidence', async () => {
    const user = userEvent.setup()

    mockedGetIndicatorCorrelation.mockResolvedValueOnce({
      indicator: '23.129.64.178',
      indicator_type: 'IPv4',
      supporting_article_count: 0,
      supporting_article_ids: [],
      supporting_articles: [],
      related_entities: emptyRelatedEntities,
      otx_enrichment: {
        indicator: '23.129.64.178',
        indicator_type: 'IPv4',
        reputation: 0,
        pulse_count: 50,
        country: 'United States of America',
        country_code: 'US',
        asn: 'AS396507 emerald onion',
        malware_families: [],
        adversaries: [],
        industries: [],
        validation: [],
        sections: ['general'],
        last_checked: '2026-08-24T08:30:00Z',
      },
      virustotal_enrichment: {
        indicator: '23.129.64.178',
        indicator_type: 'IPv4',
        report_available: false,
        resource_type: 'ip_address',
        resource_id: '23.129.64.178',
        malicious_count: 0,
        suspicious_count: 0,
        harmless_count: 0,
        undetected_count: 0,
        timeout_count: 0,
        failure_count: 0,
        type_unsupported_count: 0,
        confirmed_timeout_count: 0,
        total_engine_count: 0,
        total_result_count: 0,
        reputation: null,
        community_votes: {
          harmless: 0,
          malicious: 0,
        },
        detections: [],
        categories: [],
        tags: [],
        names: [],
        meaningful_name: null,
        file_type: null,
        country: null,
        asn: null,
        as_owner: null,
        last_analysis_date: null,
        permalink: null,
        last_checked: '2026-08-24T08:30:00Z',
        source: 'virustotal',
        cache_status: 'fresh',
        is_stale: false,
      },
    })

    mockedGetIndicatorScoring.mockResolvedValueOnce({
      target: {
        entity_type: 'indicator',
        indicator: '23.129.64.178',
        indicator_type: 'IPv4',
      },
      scoring_version: '2.0',
      threat: {
        threat_score: 10,
        threat_level: 'Low',
      },
      confidence: {
        confidence_score: 20,
        confidence_level: 'Low',
      },
      priority: {
        priority_code: 'P4',
        priority_label: 'Low',
        recommended_action: 'Gather intelligence',
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
      '23.129.64.178',
    )
    await user.click(
      screen.getByRole('button', {
        name: /investigate indicator/i,
      }),
    )

    expect(
      await screen.findByText(
        /No VirusTotal report is currently available/i,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText('50')).toBeInTheDocument()
    expect(
      screen.getByText('OTX community pulses'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('No local article sightings'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        'No related internal intelligence',
      ),
    ).toBeInTheDocument()
  })
})