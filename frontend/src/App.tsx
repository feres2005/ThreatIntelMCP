import {
  Database,
  LayoutDashboard,
  Newspaper,
  Radar,
  Search,
  ShieldCheck,
  TrendingUp,
} from 'lucide-react'
import {
  Navigate,
  NavLink,
  Route,
  Routes,
} from 'react-router-dom'

import './App.css'
import OverviewPage from './pages/OverviewPage'
import BackendStatus from './components/BackendStatus'
import TopicsPage from './pages/TopicsPage'
import ArticlesPage from './pages/ArticlesPage'
import ArticleInvestigationPage from './pages/ArticleInvestigationPage'
import { SemanticSearchPage } from './pages/SemanticSearchPage'
import IndicatorsPage from './pages/IndicatorsPage'
import IntelligencePage from './pages/IntelligencePage'

const navigation = [
  {
    label: 'Overview',
    path: '/',
    icon: LayoutDashboard,
  },
  {
    label: 'Articles',
    path: '/articles',
    icon: Newspaper,
  },
  {
    label: 'Semantic Search',
    path: '/semantic-search',
    icon: Search,
  },
  {
    label: 'Indicators',
    path: '/indicators',
    icon: Radar,
  },
  {
    label: 'Intelligence',
    path: '/intelligence',
    icon: Database,
  },
  {
    label: 'Emerging Topics',
    path: '/topics',
    icon: TrendingUp,
  },
]


function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <header className="brand">
          <ShieldCheck aria-hidden="true" />
          <div>
            <h1>ThreatIntelMCP</h1>
            <p>SOC Intelligence Console</p>
          </div>
        </header>

        <nav aria-label="Primary navigation">
          {navigation.map((item) => {
            const Icon = item.icon

            return (
              <NavLink
                key={item.path}
                to={item.path}
              >
                <Icon aria-hidden="true" />
                <span>{item.label}</span>
              </NavLink>
            )
          })}
        </nav>
        <BackendStatus />
      </aside>

      <main className="workspace">
        <Routes>
          <Route
            path="/"
            element={<OverviewPage />}
          />
          <Route
            path="/articles"
            element={<ArticlesPage />}
          />
          <Route
            path="/articles/:articleId"
            element={<ArticleInvestigationPage />}
          />          
          <Route
            path="/semantic-search"
            element={<SemanticSearchPage />}
          />
          <Route
            path="/indicators"
            element={<IndicatorsPage />}
          />
          <Route
            path="/intelligence/*"
            element={<IntelligencePage />}
          />
          <Route
            path="/topics"
            element={<TopicsPage />}
          />
          <Route
            path="*"
            element={<Navigate to="/" replace />}
          />
        </Routes>
      </main>
    </div>
  )
}

export default App