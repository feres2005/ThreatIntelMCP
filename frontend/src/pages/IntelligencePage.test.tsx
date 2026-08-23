import {
  render,
  screen,
} from '@testing-library/react'
import {
  MemoryRouter,
  Route,
  Routes,
} from 'react-router-dom'
import {
  describe,
  expect,
  it,
} from 'vitest'

import {
  IntelligencePage,
} from './IntelligencePage'

function renderIntelligencePage(
  initialPath: string,
) {
  return render(
    <MemoryRouter
      initialEntries={[initialPath]}
    >
      <Routes>
        <Route
          path="/intelligence/*"
          element={<IntelligencePage />}
        />
      </Routes>
    </MemoryRouter>,
  )
}

describe('IntelligencePage', () => {
  it('redirects the Intelligence root to CVEs', async () => {
    renderIntelligencePage('/intelligence')

    expect(
      await screen.findByRole('heading', {
        name: 'CVE Intelligence',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: 'CVEs',
      }),
    ).toHaveAttribute(
      'aria-current',
      'page',
    )

    expect(
      screen.getByRole('navigation', {
        name: 'Intelligence sections',
      }),
    ).toBeInTheDocument()
  })

  it('opens a bookmarkable Intelligence section', () => {
    renderIntelligencePage(
      '/intelligence/mitre',
    )

    expect(
      screen.getByRole('heading', {
        name: 'MITRE ATT&CK Intelligence',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('link', {
        name: 'MITRE ATT&CK',
      }),
    ).toHaveAttribute(
      'aria-current',
      'page',
    )

  })
})