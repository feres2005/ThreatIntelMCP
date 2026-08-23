import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import App from './App'

describe('App', () => {
  it('renders the SOC navigation', () => {
    render(
      <MemoryRouter>
        <App />
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('heading', {
        name: /threatintelmcp/i,
      }),
    ).toBeInTheDocument()

    for (const name of [
      'Overview',
      'Articles',
      'Semantic Search',
      'Indicators',
      'Intelligence',
      'Emerging Topics',
    ]) {
      expect(
        screen.getByRole('link', { name }),
      ).toBeInTheDocument()
    }
  })
})