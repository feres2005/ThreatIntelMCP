import {
  render,
  screen,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

const {
  mockedSearch,
  mockedEvidence,
} = vi.hoisted(() => ({
  mockedSearch: vi.fn(),
  mockedEvidence: vi.fn(),
}))

vi.mock('../../api/client', () => ({
  searchThreatEntities: mockedSearch,
  getThreatEntityEvidence: mockedEvidence,
}))

import ThreatEntitiesPanel from './ThreatEntitiesPanel'

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ThreatEntitiesPanel', () => {
  it('searches malware and opens local evidence', async () => {
    const user = userEvent.setup()

    mockedSearch.mockResolvedValue({
      entity_type: 'malware',
      keyword: 'ransom',
      limit: 10,
      offset: 0,
      returned_count: 1,
      results: [
        {
          value: 'Qilin',
          supporting_article_count: 2,
          latest_seen: (
            '2026-08-20T12:30:00Z'
          ),
        },
      ],
    })

    mockedEvidence.mockResolvedValue({
      entity_type: 'malware',
      value: 'Qilin',
      limit: 20,
      supporting_article_count: 1,
      returned_count: 1,
      articles: [
        {
          article_id: 13310,
          title: 'Qilin ransomware campaign',
          link: 'https://example.com/article',
          source: 'the_hacker_news',
          published: null,
          summary: 'Qilin targeted enterprises.',
          severity: 'High',
          confidence_score: 0.9,
          cves: ['CVE-2026-50522'],
          malware: ['Qilin'],
          mitre_techniques: ['T1486'],
          apt_groups: [],
          targeted_sectors: ['Enterprise'],
          affected_technologies: ['Windows'],
        },
      ],
    })

    render(
      <MemoryRouter>
        <ThreatEntitiesPanel />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /entity name or keyword/i,
      }),
      'ransom',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search threat entities/i,
      }),
    )

    expect(mockedSearch).toHaveBeenCalledWith({
      entityType: 'malware',
      keyword: 'ransom',
      limit: 10,
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Qilin',
      }),
    ).toBeInTheDocument()

    await user.click(
      screen.getByRole('button', {
        name: /investigate qilin/i,
      }),
    )

    expect(mockedEvidence).toHaveBeenCalledWith({
      entityType: 'malware',
      value: 'Qilin',
      limit: 20,
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Qilin ransomware campaign',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByText('T1486'),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: /open investigation/i,
      }),
    ).toHaveAttribute(
      'href',
      '/articles/13310',
    )
  })

  it('searches a selected entity category', async () => {
    const user = userEvent.setup()

    mockedSearch.mockResolvedValue({
      entity_type: 'targeted_sector',
      keyword: 'government',
      limit: 10,
      offset: 0,
      returned_count: 0,
      results: [],
    })

    render(
      <MemoryRouter>
        <ThreatEntitiesPanel />
      </MemoryRouter>,
    )

    await user.selectOptions(
      screen.getByRole('combobox', {
        name: /entity category/i,
      }),
      'targeted_sector',
    )

    await user.type(
      screen.getByRole('searchbox', {
        name: /entity name or keyword/i,
      }),
      'government',
    )

    await user.click(
      screen.getByRole('button', {
        name: /search threat entities/i,
      }),
    )

    expect(mockedSearch).toHaveBeenCalledWith({
      entityType: 'targeted_sector',
      keyword: 'government',
      limit: 10,
    })

    expect(
      await screen.findByText(
        'No matching threat entities were found.',
      ),
    ).toBeInTheDocument()
  })
})