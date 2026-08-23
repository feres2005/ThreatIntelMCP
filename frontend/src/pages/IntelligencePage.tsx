import {
  Bug,
  Crosshair,
  Network,
  ShieldCheck,
} from 'lucide-react'
import {
  Navigate,
  NavLink,
  Route,
  Routes,
} from 'react-router-dom'

import {
  CveIntelligencePanel,
} from './intelligence/CveIntelligencePanel'
import './IntelligencePage.css'
import MitreIntelligencePanel  from './intelligence/MitreIntelligencePanel'
import {
  GithubAdvisoryIntelligencePanel,
} from './intelligence/GithubAdvisoryIntelligencePanel'
import ThreatEntitiesPanel
  from './intelligence/ThreatEntitiesPanel'

const intelligenceSections = [
  {
    label: 'CVEs',
    path: '/intelligence/cves',
    icon: Bug,
  },
  {
    label: 'MITRE ATT&CK',
    path: '/intelligence/mitre',
    icon: Crosshair,
  },
  {
    label: 'GitHub Advisories',
    path: '/intelligence/advisories',
    icon: ShieldCheck,
  },
  {
    label: 'Threat Entities',
    path: '/intelligence/entities',
    icon: Network,
  },
]

export function IntelligencePage() {
  return (
    <section className="intelligence-page">
      <header className="intelligence-page-heading">
        <p>Structured threat knowledge</p>
        <h2>Intelligence Library</h2>
        <span>
          Search authoritative vulnerability,
          ATT&amp;CK and advisory datasets alongside
          article-derived threat entities.
        </span>
      </header>

      <nav
        className="intelligence-tabs"
        aria-label="Intelligence sections"
      >
        {intelligenceSections.map((section) => {
          const Icon = section.icon

          return (
            <NavLink
              key={section.path}
              to={section.path}
              className={({ isActive }) => (
                isActive
                  ? 'intelligence-tab active'
                  : 'intelligence-tab'
              )}
            >
              <Icon aria-hidden="true" />
              <span>{section.label}</span>
            </NavLink>
          )
        })}
      </nav>

      <div className="intelligence-content">
        <Routes>
          <Route
            index
            element={
              <Navigate
                to="/intelligence/cves"
                replace
              />
            }
          />

          <Route
            path="cves"
            element={<CveIntelligencePanel />}
          />

          <Route
            path="mitre"
            element={<MitreIntelligencePanel />}
          />

          <Route
            path="advisories"
            element={
              <GithubAdvisoryIntelligencePanel />
            }
          />

          <Route
            path="entities"
            element={<ThreatEntitiesPanel />}
          />

          <Route
            path="*"
            element={
              <Navigate
                to="/intelligence/cves"
                replace
              />
            }
          />
        </Routes>
      </div>
    </section>
  )
}

export default IntelligencePage